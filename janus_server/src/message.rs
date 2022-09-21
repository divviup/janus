//! DAP protocol message definitions with serialization/deserialization support.

use anyhow::anyhow;
use base64::display::Base64Display;
use derivative::Derivative;
use janus_core::{
    hpke::{associated_data_for_aggregate_share, associated_data_for_report_share},
    message::{
        query_type::{self, FixedSize, QueryType, TimeInterval},
        BatchId, HpkeCiphertext, Interval, Nonce, NonceChecksum, ReportMetadata, TaskId,
    },
};
use num_enum::TryFromPrimitive;
use postgres_types::{FromSql, ToSql};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use rand::{distributions::Standard, prelude::Distribution, Rng};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{Cursor, Read},
};

/// DAP protocol message representing one aggregator's share of a single client report.
#[derive(Derivative, Clone, PartialEq, Eq)]
#[derivative(Debug)]
pub struct ReportShare {
    metadata: ReportMetadata,
    #[derivative(Debug = "ignore")]
    public_share: Vec<u8>,
    encrypted_input_share: HpkeCiphertext,
}

impl ReportShare {
    /// Constructs a new report share from its components.
    pub fn new(
        metadata: ReportMetadata,
        public_share: Vec<u8>,
        encrypted_input_share: HpkeCiphertext,
    ) -> Self {
        Self {
            metadata,
            public_share,
            encrypted_input_share,
        }
    }

    /// Gets the metadata associated with this report share.
    pub fn metadata(&self) -> &ReportMetadata {
        &self.metadata
    }

    /// Gets the public share associated with this report share.
    pub fn public_share(&self) -> &[u8] {
        &self.public_share
    }

    /// Gets the encrypted input share associated with this report share.
    pub fn encrypted_input_share(&self) -> &HpkeCiphertext {
        &self.encrypted_input_share
    }

    pub(crate) fn associated_data(&self, task_id: TaskId) -> Vec<u8> {
        associated_data_for_report_share(task_id, &self.metadata)
    }
}

impl Encode for ReportShare {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.metadata.encode(bytes);
        encode_u16_items(bytes, &(), &self.public_share); // TODO(#471): should be encode_u32_items
        self.encrypted_input_share.encode(bytes);
    }
}

impl Decode for ReportShare {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let metadata = ReportMetadata::decode(bytes)?;
        let public_share = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items
        let encrypted_input_share = HpkeCiphertext::decode(bytes)?;

        Ok(Self {
            metadata,
            public_share,
            encrypted_input_share,
        })
    }
}

/// DAP protocol message representing the result of a preparation step in a VDAF evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareStep {
    nonce: Nonce,
    result: PrepareStepResult,
}

impl PrepareStep {
    /// Constructs a new prepare step from its components.
    pub fn new(nonce: Nonce, result: PrepareStepResult) -> Self {
        Self { nonce, result }
    }

    /// Gets the nonce associated with this prepare step.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Gets the result associated with this prepare step.
    pub fn result(&self) -> &PrepareStepResult {
        &self.result
    }
}

impl Encode for PrepareStep {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.nonce.encode(bytes);
        self.result.encode(bytes);
    }
}

impl Decode for PrepareStep {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let nonce = Nonce::decode(bytes)?;
        let result = PrepareStepResult::decode(bytes)?;

        Ok(Self { nonce, result })
    }
}

/// DAP protocol message representing result-type-specific data associated with a preparation step
/// in a VDAF evaluation. Included in a PrepareStep message.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub enum PrepareStepResult {
    Continued(#[derivative(Debug = "ignore")] Vec<u8>), // content is a serialized preparation message
    Finished,
    Failed(ReportShareError),
}

impl Encode for PrepareStepResult {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // The encoding includes an implicit discriminator byte, called PrepareStepResult in the
        // DAP spec.
        match self {
            Self::Continued(vdaf_msg) => {
                0u8.encode(bytes);
                encode_u16_items(bytes, &(), vdaf_msg); // TODO(#471): should be encode_u32_items
            }
            Self::Finished => 1u8.encode(bytes),
            Self::Failed(error) => {
                2u8.encode(bytes);
                error.encode(bytes);
            }
        }
    }
}

impl Decode for PrepareStepResult {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Ok(match val {
            0 => Self::Continued(decode_u16_items(&(), bytes)?), // TODO(#471): should be decode_u32_items
            1 => Self::Finished,
            2 => Self::Failed(ReportShareError::decode(bytes)?),
            _ => return Err(CodecError::UnexpectedValue),
        })
    }
}

/// DAP protocol message representing an error while preparing a report share for aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, ToSql, FromSql)]
#[repr(u8)]
pub enum ReportShareError {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
    BatchSaturated = 6,
    TaskExpired = 7,
}

impl Encode for ReportShareError {
    fn encode(&self, bytes: &mut Vec<u8>) {
        (*self as u8).encode(bytes);
    }
}

impl Decode for ReportShareError {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u8::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected ReportShareError value {}", val).into())
        })
    }
}

/// DAP protocol message representing an identifier for an aggregation job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AggregationJobId([u8; Self::ENCODED_LEN]);

impl AggregationJobId {
    /// ENCODED_LEN is the length of an aggregation job ID in bytes when encoded.
    const ENCODED_LEN: usize = 32;
}

impl AsRef<[u8; Self::ENCODED_LEN]> for AggregationJobId {
    fn as_ref(&self) -> &[u8; Self::ENCODED_LEN] {
        &self.0
    }
}

impl Debug for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AggregationJobId({})",
            Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
        )
    }
}

impl Display for AggregationJobId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            Base64Display::with_config(&self.0, base64::URL_SAFE_NO_PAD)
        )
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

impl Distribution<AggregationJobId> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AggregationJobId {
        AggregationJobId(rng.gen())
    }
}

/// DAP protocol message representing an aggregation initialization request from leader to helper.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct AggregateInitializeReq<Q: QueryType> {
    task_id: TaskId,
    job_id: AggregationJobId,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
    batch_identifier: Q::AggregateInitializeReqBatchIdentifier,
    report_shares: Vec<ReportShare>,
}

impl<Q: QueryType> AggregateInitializeReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-initialize-req";

    /// Constructs an aggregate initialization request from its components.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].

    pub fn new(
        task_id: TaskId,
        job_id: AggregationJobId,
        aggregation_parameter: Vec<u8>,
        batch_identifier: Q::AggregateInitializeReqBatchIdentifier,
        report_shares: Vec<ReportShare>,
    ) -> Self {
        Self {
            task_id,
            job_id,
            aggregation_parameter,
            batch_identifier,
            report_shares,
        }
    }

    /// Gets the task ID associated with this aggregate initialization request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the aggregation job ID associated with this aggregate initialization request.
    pub fn job_id(&self) -> &AggregationJobId {
        &self.job_id
    }

    /// Gets the aggregation parameter associated with this aggregate initialization request.
    pub fn aggregation_parameter(&self) -> &[u8] {
        &self.aggregation_parameter
    }

    /// Gets the batch identifier associated with this aggregate initialization request.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::AggregateInitializeReqBatchIdentifier {
        &self.batch_identifier
    }

    /// Gets the report shares associated with this aggregate initialization request.
    pub fn report_shares(&self) -> &[ReportShare] {
        &self.report_shares
    }
}

impl AggregateInitializeReq<TimeInterval> {
    /// Constructs a new aggregate initialization request for a time-interval task.
    pub fn new_time_interval(
        task_id: TaskId,
        job_id: AggregationJobId,
        aggregation_parameter: Vec<u8>,
        report_shares: Vec<ReportShare>,
    ) -> Self {
        Self::new(task_id, job_id, aggregation_parameter, (), report_shares)
    }
}

impl AggregateInitializeReq<FixedSize> {
    /// Constructs a new aggregate initialization request for a fixed-size task.
    pub fn new_fixed_size(
        task_id: TaskId,
        job_id: AggregationJobId,
        aggregation_parameter: Vec<u8>,
        batch_id: BatchId,
        report_shares: Vec<ReportShare>,
    ) -> Self {
        Self::new(
            task_id,
            job_id,
            aggregation_parameter,
            batch_id,
            report_shares,
        )
    }

    /// Gets the batch ID associated with this aggregate initialization request.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<Q: QueryType> Encode for AggregateInitializeReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.aggregation_parameter);
        Q::CODE.encode(bytes);
        self.batch_identifier.encode(bytes);
        encode_u16_items(bytes, &(), &self.report_shares); // TODO(#471): should be encode_u32_items
    }
}

impl<Q: QueryType> Decode for AggregateInitializeReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let aggregation_parameter = decode_u16_items(&(), bytes)?;
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::AggregateInitializeReqBatchIdentifier::decode(bytes)?;
        let report_shares = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items
        Ok(Self {
            task_id,
            job_id,
            aggregation_parameter,
            batch_identifier,
            report_shares,
        })
    }
}

/// DAP protocol message representing an aggregation initialization response from helper to leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateInitializeResp {
    prepare_steps: Vec<PrepareStep>,
}

impl AggregateInitializeResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-initialize-resp";

    /// Constructs a new aggregate initialization response from its components.
    pub fn new(prepare_steps: Vec<PrepareStep>) -> Self {
        Self { prepare_steps }
    }

    /// Gets the prepare steps associated with this aggregate initialization response.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregateInitializeResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.prepare_steps); // TODO(#471): should be encode_u32_items
    }
}

impl Decode for AggregateInitializeResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let prepare_steps = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items
        Ok(Self { prepare_steps })
    }
}

/// DAP protocol message representing an aggregation continuation request from leader to helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueReq {
    task_id: TaskId,
    job_id: AggregationJobId,
    prepare_steps: Vec<PrepareStep>,
}

impl AggregateContinueReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-continue-req";

    /// Constructs a new aggregate continuation request from its components.
    pub fn new(task_id: TaskId, job_id: AggregationJobId, prepare_steps: Vec<PrepareStep>) -> Self {
        Self {
            task_id,
            job_id,
            prepare_steps,
        }
    }

    /// Gets the task ID associated with this aggregate continuation request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the aggregation job ID associated with this aggregate continuation request.
    pub fn job_id(&self) -> &AggregationJobId {
        &self.job_id
    }

    /// Gets the prepare steps associated with this aggregate continuation request.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregateContinueReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.prepare_steps); // TODO(#471): should be encode_u32_items
    }
}

impl Decode for AggregateContinueReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let prepare_steps = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items
        Ok(Self {
            task_id,
            job_id,
            prepare_steps,
        })
    }
}

/// DAP protocol message representing an aggregation continue response from helper to leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueResp {
    prepare_steps: Vec<PrepareStep>,
}

impl AggregateContinueResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-continue-resp";

    /// Constructs a new aggregate continuation response from its components.
    pub fn new(prepare_steps: Vec<PrepareStep>) -> Self {
        Self { prepare_steps }
    }

    /// Gets the prepare steps associated with this aggregate continuation response.
    pub fn prepare_steps(&self) -> &[PrepareStep] {
        &self.prepare_steps
    }
}

impl Encode for AggregateContinueResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.prepare_steps); // TODO(#471): should be encode_u32_items
    }
}

impl Decode for AggregateContinueResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let prepare_steps = decode_u16_items(&(), bytes)?; // TODO(#471): should be decode_u32_items
        Ok(Self { prepare_steps })
    }
}

/// DAP protocol message identifying a batch of interest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSelector<Q: QueryType> {
    batch_identifier: Q::BatchIdentifier,
}

impl<Q: QueryType> BatchSelector<Q> {
    /// Constructs a new batch selector from its components.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::new_time_interval`] or
    /// [`Self::new_fixed_size`].
    pub fn new(batch_identifier: Q::BatchIdentifier) -> Self {
        Self { batch_identifier }
    }

    /// Gets the batch identifier associated with this batch selector.
    ///
    /// This method would typically be used for code which is generic over the query type.
    /// Query-type specific code will typically call one of [`Self::batch_interval`] or
    /// [`Self::batch_id`].
    pub fn batch_identifier(&self) -> &Q::BatchIdentifier {
        &self.batch_identifier
    }
}

impl BatchSelector<TimeInterval> {
    /// Constructs a new batch selector for time-interval tasks.
    pub fn new_time_interval(batch_interval: Interval) -> Self {
        Self::new(batch_interval)
    }

    /// Gets the batch interval associated with this batch selector.
    pub fn batch_interval(&self) -> &Interval {
        self.batch_identifier()
    }
}

impl BatchSelector<FixedSize> {
    /// Constructs a new batch selector for fixed-size tasks.
    pub fn new_fixed_size(batch_id: BatchId) -> Self {
        Self::new(batch_id)
    }

    /// Gets the batch ID associated with this batch selector.
    pub fn batch_id(&self) -> &BatchId {
        self.batch_identifier()
    }
}

impl<Q: QueryType> Encode for BatchSelector<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        Q::CODE.encode(bytes);
        self.batch_identifier.encode(bytes);
    }
}

impl<Q: QueryType> Decode for BatchSelector<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        query_type::Code::decode_expecting_value(bytes, Q::CODE)?;
        let batch_identifier = Q::BatchIdentifier::decode(bytes)?;

        Ok(Self { batch_identifier })
    }
}

/// DAP protocol message representing a request from the leader to a helper to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Derivative, PartialEq, Eq)]
#[derivative(Debug)]
pub struct AggregateShareReq<Q: QueryType> {
    task_id: TaskId,
    batch_selector: BatchSelector<Q>,
    #[derivative(Debug = "ignore")]
    aggregation_parameter: Vec<u8>,
    report_count: u64,
    checksum: NonceChecksum,
}

impl<Q: QueryType> AggregateShareReq<Q> {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-share-req";

    /// Constructs a new aggregate share request from its components.
    pub fn new(
        task_id: TaskId,
        batch_selector: BatchSelector<Q>,
        aggregation_parameter: Vec<u8>,
        report_count: u64,
        checksum: NonceChecksum,
    ) -> Self {
        Self {
            task_id,
            batch_selector,
            aggregation_parameter,
            report_count,
            checksum,
        }
    }

    /// Gets the task ID associated with this aggregate share request.
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Gets the batch selector associated with this aggregate share request.
    pub fn batch_selector(&self) -> &BatchSelector<Q> {
        &self.batch_selector
    }

    /// Gets the aggregation parameter associated with this aggregate share request.
    pub fn aggregation_parameter(&self) -> &[u8] {
        &self.aggregation_parameter
    }

    /// Gets the report count associated with this aggregate share request.
    pub fn report_count(&self) -> u64 {
        self.report_count
    }

    /// Gets the checksum associated with this aggregate share request.
    pub fn checksum(&self) -> &NonceChecksum {
        &self.checksum
    }

    pub(crate) fn associated_data_for_aggregate_share(&self) -> Vec<u8> {
        associated_data_for_aggregate_share::<Q>(
            self.task_id,
            &self.batch_selector.batch_identifier,
        )
    }
}

impl<Q: QueryType> Encode for AggregateShareReq<Q> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_selector.encode(bytes);
        encode_u16_items(bytes, &(), &self.aggregation_parameter);
        self.report_count.encode(bytes);
        self.checksum.encode(bytes);
    }
}

impl<Q: QueryType> Decode for AggregateShareReq<Q> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_selector = BatchSelector::decode(bytes)?;
        let aggregation_parameter = decode_u16_items(&(), bytes)?;
        let report_count = u64::decode(bytes)?;
        let checksum = NonceChecksum::decode(bytes)?;

        Ok(Self {
            task_id,
            batch_selector,
            aggregation_parameter,
            report_count,
            checksum,
        })
    }
}

/// DAP protocol message representing a helper's response to the leader's request to provide an
/// encrypted aggregate of its share of data for a given batch interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateShareResp {
    encrypted_aggregate_share: HpkeCiphertext,
}

impl AggregateShareResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "application/dap-aggregate-share-resp";

    /// Constructs a new aggregate share response from its components.
    pub fn new(encrypted_aggregate_share: HpkeCiphertext) -> Self {
        Self {
            encrypted_aggregate_share,
        }
    }

    /// Gets the encrypted aggregate share associated with this aggregate share response.
    pub fn encrypted_aggregate_share(&self) -> &HpkeCiphertext {
        &self.encrypted_aggregate_share
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::message::{
        test_util::roundtrip_encoding, Duration, Extension, ExtensionType, HpkeConfigId, Time,
    };

    #[test]
    fn roundtrip_prepare_step() {
        roundtrip_encoding(&[
            (
                PrepareStep {
                    nonce: Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    result: PrepareStepResult::Continued(Vec::from("012345")),
                },
                concat!(
                    "0102030405060708090a0b0c0d0e0f10", // nonce
                    "00",                               // prepare_step_result
                    concat!(
                        // vdaf_msg
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
            (
                PrepareStep {
                    nonce: Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    result: PrepareStepResult::Finished,
                },
                concat!(
                    "100f0e0d0c0b0a090807060504030201", // nonce
                    "01",                               // prepare_step_result
                ),
            ),
            (
                PrepareStep {
                    nonce: Nonce::from([255; 16]),
                    result: PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // nonce
                    "02",                               // prepare_step_result
                    "05",                               // report_share_error
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report_share_error() {
        roundtrip_encoding(&[
            (ReportShareError::BatchCollected, "00"),
            (ReportShareError::ReportReplayed, "01"),
            (ReportShareError::ReportDropped, "02"),
            (ReportShareError::HpkeUnknownConfigId, "03"),
            (ReportShareError::HpkeDecryptError, "04"),
            (ReportShareError::VdafPrepError, "05"),
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
    fn roundtrip_aggregate_initialize_req() {
        // TimeInterval.
        roundtrip_encoding(&[(
            AggregateInitializeReq::<TimeInterval> {
                task_id: TaskId::from([u8::MAX; 32]),
                job_id: AggregationJobId([u8::MIN; 32]),
                aggregation_parameter: Vec::from("012345"),
                batch_identifier: (),
                report_shares: vec![
                    ReportShare {
                        metadata: ReportMetadata::new(
                            Time::from_seconds_since_epoch(54321),
                            Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                            vec![Extension::new(ExtensionType::Tbd, Vec::from("0123"))],
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    ReportShare {
                        metadata: ReportMetadata::new(
                            Time::from_seconds_since_epoch(73542),
                            Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            vec![Extension::new(ExtensionType::Tbd, Vec::from("3210"))],
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                ],
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                concat!(
                    // aggregation_parameter
                    "0006",         // length
                    "303132333435", // opaque data
                ),
                "0001", // query_type
                concat!(
                    // report_shares
                    "006A", // length
                    concat!(
                        concat!(
                            // metadata
                            "000000000000D431",                 // time
                            "0102030405060708090a0b0c0d0e0f10", // nonce
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
                        ),
                        concat!(
                            // public_share
                            "0000", // length
                            "",     // opaque data
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
                            // metadata
                            "0000000000011F46",                 // time
                            "100F0E0D0C0B0A090807060504030201", // nonce
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
                        ),
                        concat!(
                            "0004",     // payload
                            "30313233", // opaque data
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
                                // payload
                                "0004",     // length
                                "61626664", // opaque data
                            ),
                        ),
                    ),
                ),
            ),
        )]);

        // FixedSize.
        roundtrip_encoding(&[(
            AggregateInitializeReq::<FixedSize> {
                task_id: TaskId::from([u8::MAX; 32]),
                job_id: AggregationJobId([u8::MIN; 32]),
                aggregation_parameter: Vec::from("012345"),
                batch_identifier: BatchId::from([2u8; 32]),
                report_shares: vec![
                    ReportShare {
                        metadata: ReportMetadata::new(
                            Time::from_seconds_since_epoch(54321),
                            Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                            vec![Extension::new(ExtensionType::Tbd, Vec::from("0123"))],
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    ReportShare {
                        metadata: ReportMetadata::new(
                            Time::from_seconds_since_epoch(73542),
                            Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            vec![Extension::new(ExtensionType::Tbd, Vec::from("3210"))],
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                ],
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // task_id
                "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                concat!(
                    // aggregation_parameter
                    "0006",         // length
                    "303132333435", // opaque data
                ),
                "0002", // query_type
                "0202020202020202020202020202020202020202020202020202020202020202", // batch_id
                concat!(
                    // report_shares
                    "006A", // length
                    concat!(
                        concat!(
                            // metadata
                            "000000000000D431",                 // time
                            "0102030405060708090a0b0c0d0e0f10", // nonce
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
                        ),
                        concat!(
                            // public_share
                            "0000", // length
                            "",     // opaque data
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
                            // metadata
                            "0000000000011F46",                 // time
                            "100F0E0D0C0B0A090807060504030201", // nonce
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
                        ),
                        concat!(
                            "0004",     // payload
                            "30313233", // opaque data
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
                                // payload
                                "0004",     // length
                                "61626664", // opaque data
                            ),
                        ),
                    ),
                ),
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregate_initialize_resp() {
        roundtrip_encoding(&[
            (
                AggregateInitializeResp {
                    prepare_steps: vec![],
                },
                concat!(concat!(
                    // prepare_steps
                    "0000", // length
                ),),
            ),
            (
                AggregateInitializeResp {
                    prepare_steps: vec![
                        PrepareStep {
                            nonce: Nonce::from([
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            ]),
                            result: PrepareStepResult::Continued(Vec::from("012345")),
                        },
                        PrepareStep {
                            nonce: Nonce::from([
                                16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                            ]),
                            result: PrepareStepResult::Finished,
                        },
                    ],
                },
                concat!(concat!(
                    // prepare_steps
                    "002A", // length
                    concat!(
                        "0102030405060708090a0b0c0d0e0f10", // nonce
                        "00",                               // prepare_step_result
                        concat!(
                            // payload
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        "100f0e0d0c0b0a090807060504030201", // nonce
                        "01",                               // prepare_step_result
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_continue_req() {
        roundtrip_encoding(&[(
            AggregateContinueReq {
                task_id: TaskId::from([u8::MIN; 32]),
                job_id: AggregationJobId([u8::MAX; 32]),
                prepare_steps: vec![
                    PrepareStep {
                        nonce: Nonce::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        result: PrepareStepResult::Continued(Vec::from("012345")),
                    },
                    PrepareStep {
                        nonce: Nonce::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        result: PrepareStepResult::Finished,
                    },
                ],
            },
            concat!(
                "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                concat!(
                    // prepare_steps
                    "002A", // length
                    concat!(
                        "0102030405060708090a0b0c0d0e0f10", // nonce
                        "00",                               // prepare_step_result
                        concat!(
                            // payload
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        "100f0e0d0c0b0a090807060504030201", // nonce
                        "01",                               // prepare_step_result
                    )
                ),
            ),
        )])
    }

    #[test]
    fn roundtrip_aggregate_continue_resp() {
        roundtrip_encoding(&[
            (
                AggregateContinueResp {
                    prepare_steps: vec![],
                },
                concat!(concat!(
                    // prepare_steps
                    "0000", // length
                ),),
            ),
            (
                AggregateContinueResp {
                    prepare_steps: vec![
                        PrepareStep {
                            nonce: Nonce::from([
                                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            ]),
                            result: PrepareStepResult::Continued(Vec::from("012345")),
                        },
                        PrepareStep {
                            nonce: Nonce::from([
                                16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                            ]),
                            result: PrepareStepResult::Finished,
                        },
                    ],
                },
                concat!(concat!(
                    // prepare_steps
                    "002A", // length
                    concat!(
                        "0102030405060708090a0b0c0d0e0f10", // nonce
                        "00",                               // prepare_step_result
                        concat!(
                            // payload
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                    ),
                    concat!(
                        "100f0e0d0c0b0a090807060504030201", // nonce
                        "01",                               // prepare_step_result
                    ),
                )),
            ),
        ])
    }

    #[test]
    fn roundtrip_batch_selector() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                BatchSelector::<TimeInterval> {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                },
                concat!(
                    "0001", // query_type
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                ),
            ),
            (
                BatchSelector::<TimeInterval> {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(50821),
                        Duration::from_seconds(84354),
                    )
                    .unwrap(),
                },
                concat!(
                    "0001", // query_type
                    concat!(
                        // batch_interval
                        "000000000000C685", // start
                        "0000000000014982", // duration
                    ),
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                BatchSelector::<FixedSize> {
                    batch_identifier: BatchId::from([12u8; 32]),
                },
                concat!(
                    // batch_selector
                    "0002", // query_type
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // batch_id
                ),
            ),
            (
                BatchSelector::<FixedSize> {
                    batch_identifier: BatchId::from([7u8; 32]),
                },
                concat!(
                    "0002",                                                             // query_type
                    "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_share_req() {
        // TimeInterval.
        roundtrip_encoding(&[
            (
                AggregateShareReq::<TimeInterval> {
                    task_id: TaskId::from([u8::MIN; 32]),
                    batch_selector: BatchSelector {
                        batch_identifier: Interval::new(
                            Time::from_seconds_since_epoch(54321),
                            Duration::from_seconds(12345),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::new(),
                    report_count: 439,
                    checksum: NonceChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // batch_selector
                        "0001", // query_type
                        concat!(
                            // batch_interval
                            "000000000000D431", // start
                            "0000000000003039", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "0000", // length
                        "",     // opaque data
                    ),
                    "00000000000001B7", // report_count
                    "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                ),
            ),
            (
                AggregateShareReq::<TimeInterval> {
                    task_id: TaskId::from([12u8; 32]),
                    batch_selector: BatchSelector {
                        batch_identifier: Interval::new(
                            Time::from_seconds_since_epoch(50821),
                            Duration::from_seconds(84354),
                        )
                        .unwrap(),
                    },
                    aggregation_parameter: Vec::from("012345"),
                    report_count: 8725,
                    checksum: NonceChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
                },
                concat!(
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
                    concat!(
                        // batch_selector
                        "0001", // query_type
                        concat!(
                            // batch_interval
                            "000000000000C685", // start
                            "0000000000014982", // duration
                        ),
                    ),
                    concat!(
                        // aggregation_parameter
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                    "0000000000002215", // report_count
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                ),
            ),
        ]);

        // FixedSize.
        roundtrip_encoding(&[
            (
                AggregateShareReq::<FixedSize> {
                    task_id: TaskId::from([u8::MIN; 32]),
                    batch_selector: BatchSelector {
                        batch_identifier: BatchId::from([12u8; 32]),
                    },
                    aggregation_parameter: Vec::new(),
                    report_count: 439,
                    checksum: NonceChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // task_id
                    concat!(
                        // batch_selector
                        "0002", // query_type
                        "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "0000", // length
                        "",     // opaque data
                    ),
                    "00000000000001B7", // report_count
                    "0000000000000000000000000000000000000000000000000000000000000000", // checksum
                ),
            ),
            (
                AggregateShareReq::<FixedSize> {
                    task_id: TaskId::from([12u8; 32]),
                    batch_selector: BatchSelector {
                        batch_identifier: BatchId::from([7u8; 32]),
                    },
                    aggregation_parameter: Vec::from("012345"),
                    report_count: 8725,
                    checksum: NonceChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
                },
                concat!(
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
                    concat!(
                        // batch_selector
                        "0002", // query_type
                        "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
                    ),
                    concat!(
                        // aggregation_parameter
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                    "0000000000002215", // report_count
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
                ),
            ),
        ]);
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
}
