//! PPM protocol message definitions with serialization/deserialization support.

use anyhow::anyhow;
use base64::display::Base64Display;
use janus::{
    hpke::{associated_data_for_aggregate_share, associated_data_for_report_share},
    message::{Extension, HpkeCiphertext, Interval, Nonce, NonceChecksum, TaskId},
};
use num_enum::TryFromPrimitive;
use postgres_types::{FromSql, ToSql};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use rand::{thread_rng, Rng};
use std::{
    fmt::{Debug, Display, Formatter},
    io::{Cursor, Read},
};

/// PPM protocol message representing one aggregator's share of a single client report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportShare {
    pub nonce: Nonce,
    pub extensions: Vec<Extension>,
    pub encrypted_input_share: HpkeCiphertext,
}

impl ReportShare {
    pub(crate) fn associated_data(&self, task_id: TaskId) -> Vec<u8> {
        associated_data_for_report_share(task_id, self.nonce, &self.extensions)
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

/// DAP protocol message representing the result of a preparation step in a VDAF evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrepareStep {
    pub nonce: Nonce,
    pub result: PrepareStepResult,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareStepResult {
    Continued(Vec<u8>), // content is a serialized preparation message
    Finished,
    Failed(ReportShareError),
}

impl Encode for PrepareStepResult {
    fn encode(&self, bytes: &mut Vec<u8>) {
        // The encoding includes an implicit discriminator byte, called PrepareStepResult in the
        // DAP spec.
        match self {
            Self::Continued(prep_msg) => {
                0u8.encode(bytes);
                encode_u16_items(bytes, &(), prep_msg);
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
            0 => Self::Continued(decode_u16_items(&(), bytes)?),
            1 => Self::Finished,
            2 => Self::Failed(ReportShareError::decode(bytes)?),
            _ => return Err(CodecError::UnexpectedValue),
        })
    }
}

/// PPM protocol message representing an error while preparing a report share for aggregation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive, ToSql, FromSql)]
#[repr(u8)]
pub enum ReportShareError {
    BatchCollected = 0,
    ReportReplayed = 1,
    ReportDropped = 2,
    HpkeUnknownConfigId = 3,
    HpkeDecryptError = 4,
    VdafPrepError = 5,
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

/// DAP protocol message representing an aggregation initialization request from leader to helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateInitializeReq {
    pub task_id: TaskId,
    pub job_id: AggregationJobId,
    pub agg_param: Vec<u8>,
    pub report_shares: Vec<ReportShare>,
}

impl AggregateInitializeReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-aggregate-initialize-req";
}

impl Encode for AggregateInitializeReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.agg_param);
        encode_u16_items(bytes, &(), &self.report_shares);
    }
}

impl Decode for AggregateInitializeReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let job_id = AggregationJobId::decode(bytes)?;
        let agg_param = decode_u16_items(&(), bytes)?;
        let report_shares = decode_u16_items(&(), bytes)?;
        Ok(AggregateInitializeReq {
            task_id,
            job_id,
            agg_param,
            report_shares,
        })
    }
}

/// DAP protocol message representing an aggregation initialization response from helper to leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateInitializeResp {
    pub job_id: AggregationJobId,
    pub prepare_steps: Vec<PrepareStep>,
}

impl AggregateInitializeResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-aggregate-initialize-resp";
}

impl Encode for AggregateInitializeResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.prepare_steps);
    }
}

impl Decode for AggregateInitializeResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let job_id = AggregationJobId::decode(bytes)?;
        let prepare_steps = decode_u16_items(&(), bytes)?;
        Ok(Self {
            job_id,
            prepare_steps,
        })
    }
}

/// DAP protocol message representing an aggregation continuation request from leader to helper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueReq {
    pub job_id: AggregationJobId,
    pub prepare_steps: Vec<PrepareStep>,
}

impl AggregateContinueReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-aggregate-continue-req";
}

impl Encode for AggregateContinueReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.prepare_steps);
    }
}

impl Decode for AggregateContinueReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let job_id = AggregationJobId::decode(bytes)?;
        let prepare_steps = decode_u16_items(&(), bytes)?;
        Ok(Self {
            job_id,
            prepare_steps,
        })
    }
}

/// DAP protocol message representing an aggregation continue response from helper to leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateContinueResp {
    pub job_id: AggregationJobId,
    pub prepare_steps: Vec<PrepareStep>,
}

impl AggregateContinueResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-aggregate-continue-resp";
}

impl Encode for AggregateContinueResp {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.job_id.encode(bytes);
        encode_u16_items(bytes, &(), &self.prepare_steps);
    }
}

impl Decode for AggregateContinueResp {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let job_id = AggregationJobId::decode(bytes)?;
        let prepare_steps = decode_u16_items(&(), bytes)?;
        Ok(Self {
            job_id,
            prepare_steps,
        })
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
    pub(crate) checksum: NonceChecksum,
}

impl AggregateShareReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-aggregate-share-req";

    pub(crate) fn associated_data_for_aggregate_share(&self) -> Vec<u8> {
        associated_data_for_aggregate_share(self.task_id, self.batch_interval)
    }
}

impl Encode for AggregateShareReq {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        encode_u16_items(bytes, &(), &self.aggregation_param);
        self.report_count.encode(bytes);
        self.checksum.encode(bytes);
    }
}

impl Decode for AggregateShareReq {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        let agg_param = decode_u16_items(&(), bytes)?;
        let report_count = u64::decode(bytes)?;
        let checksum = NonceChecksum::decode(bytes)?;

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

impl AggregateShareResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-aggregate-share-resp";
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

impl CollectReq {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-collect-req";
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

impl CollectResp {
    /// The media type associated with this protocol message.
    pub const MEDIA_TYPE: &'static str = "message/dap-collect-resp";
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
    use janus::message::{Duration, ExtensionType, HpkeConfigId, Time};

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
    fn roundtrip_prepare_step() {
        roundtrip_encoding(&[
            (
                PrepareStep {
                    nonce: Nonce::new(
                        Time::from_seconds_since_epoch(54372),
                        [1, 2, 3, 4, 5, 6, 7, 8],
                    ),
                    result: PrepareStepResult::Continued(Vec::from("012345")),
                },
                concat!(
                    concat!(
                        // nonce
                        "000000000000D464", // time
                        "0102030405060708", // rand
                    ),
                    "00", // prepare_step_result
                    concat!(
                        // prep_msg
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                ),
            ),
            (
                PrepareStep {
                    nonce: Nonce::new(
                        Time::from_seconds_since_epoch(12345),
                        [8, 7, 6, 5, 4, 3, 2, 1],
                    ),
                    result: PrepareStepResult::Finished,
                },
                concat!(
                    concat!(
                        // nonce
                        "0000000000003039", // time
                        "0807060504030201", // rand
                    ),
                    "01", // prepare_step_result
                ),
            ),
            (
                PrepareStep {
                    nonce: Nonce::new(Time::from_seconds_since_epoch(345078), [255; 8]),
                    result: PrepareStepResult::Failed(ReportShareError::VdafPrepError),
                },
                concat!(
                    concat!(
                        // nonce
                        "00000000000543F6", // time
                        "FFFFFFFFFFFFFFFF", // rand
                    ),
                    "02", // prepare_step_result
                    "05", // report_share_error
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_report_share_error() {
        roundtrip_encoding(&[
            (ReportShareError::BatchCollected, "00"),
            (ReportShareError::HpkeDecryptError, "04"),
            (ReportShareError::HpkeUnknownConfigId, "03"),
            (ReportShareError::ReportDropped, "02"),
            (ReportShareError::ReportReplayed, "01"),
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
        roundtrip_encoding(&[(
            AggregateInitializeReq {
                task_id: TaskId::new([u8::MAX; 32]),
                job_id: AggregationJobId([u8::MIN; 32]),
                agg_param: Vec::from("012345"),
                report_shares: vec![
                    ReportShare {
                        nonce: Nonce::new(
                            Time::from_seconds_since_epoch(54321),
                            [1, 2, 3, 4, 5, 6, 7, 8],
                        ),
                        extensions: vec![Extension::new(ExtensionType::Tbd, Vec::from("0123"))],
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
                        extensions: vec![Extension::new(ExtensionType::Tbd, Vec::from("3210"))],
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
                    // agg_param
                    "0006",         // length
                    "303132333435", // opaque data
                ),
                concat!(
                    // report_shares
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
        )])
    }

    #[test]
    fn roundtrip_aggregate_initialize_resp() {
        roundtrip_encoding(&[
            (
                AggregateInitializeResp {
                    job_id: AggregationJobId([u8::MIN; 32]),
                    prepare_steps: vec![],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                    concat!(
                        // prepare_steps
                        "0000", // length
                    ),
                ),
            ),
            (
                AggregateInitializeResp {
                    job_id: AggregationJobId([u8::MAX; 32]),
                    prepare_steps: vec![
                        PrepareStep {
                            nonce: Nonce::new(
                                Time::from_seconds_since_epoch(54372),
                                [1, 2, 3, 4, 5, 6, 7, 8],
                            ),
                            result: PrepareStepResult::Continued(Vec::from("012345")),
                        },
                        PrepareStep {
                            nonce: Nonce::new(
                                Time::from_seconds_since_epoch(12345),
                                [8, 7, 6, 5, 4, 3, 2, 1],
                            ),
                            result: PrepareStepResult::Finished,
                        },
                    ],
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                    concat!(
                        //prepare_steps
                        "002A", // length
                        concat!(
                            concat!(
                                // nonce
                                "000000000000D464", // time
                                "0102030405060708", // rand
                            ),
                            "00", // prepare_step_result
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
                            "01", // prepare_step_result
                        ),
                    )
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_aggregate_continue_req() {
        roundtrip_encoding(&[(
            AggregateContinueReq {
                job_id: AggregationJobId([u8::MAX; 32]),
                prepare_steps: vec![
                    PrepareStep {
                        nonce: Nonce::new(
                            Time::from_seconds_since_epoch(54372),
                            [1, 2, 3, 4, 5, 6, 7, 8],
                        ),
                        result: PrepareStepResult::Continued(Vec::from("012345")),
                    },
                    PrepareStep {
                        nonce: Nonce::new(
                            Time::from_seconds_since_epoch(12345),
                            [8, 7, 6, 5, 4, 3, 2, 1],
                        ),
                        result: PrepareStepResult::Finished,
                    },
                ],
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                concat!(
                    // prepare_steps
                    "002A", // length
                    concat!(
                        concat!(
                            // nonce
                            "000000000000D464", // time
                            "0102030405060708", // rand
                        ),
                        "00", // prepare_step_result
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
                        "01", // prepare_step_result
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
                    job_id: AggregationJobId([u8::MIN; 32]),
                    prepare_steps: vec![],
                },
                concat!(
                    "0000000000000000000000000000000000000000000000000000000000000000", // job_id
                    concat!(
                        // prepare_steps
                        "0000", // length
                    ),
                ),
            ),
            (
                AggregateContinueResp {
                    job_id: AggregationJobId([u8::MAX; 32]),
                    prepare_steps: vec![
                        PrepareStep {
                            nonce: Nonce::new(
                                Time::from_seconds_since_epoch(54372),
                                [1, 2, 3, 4, 5, 6, 7, 8],
                            ),
                            result: PrepareStepResult::Continued(Vec::from("012345")),
                        },
                        PrepareStep {
                            nonce: Nonce::new(
                                Time::from_seconds_since_epoch(12345),
                                [8, 7, 6, 5, 4, 3, 2, 1],
                            ),
                            result: PrepareStepResult::Finished,
                        },
                    ],
                },
                concat!(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // job_id
                    concat!(
                        //prepare_steps
                        "002A", // length
                        concat!(
                            concat!(
                                // nonce
                                "000000000000D464", // time
                                "0102030405060708", // rand
                            ),
                            "00", // prepare_step_result
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
                            "01", // prepare_step_result
                        ),
                    )
                ),
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
                    checksum: NonceChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
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
                    checksum: NonceChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
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
