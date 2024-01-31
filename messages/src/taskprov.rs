//! Data structures as defined in extension [draft-wang-ppm-dap-taskprov][1].
//!
//! [1]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/

use crate::{Duration, Error, Time, Url};
use anyhow::anyhow;
use derivative::Derivative;
use prio::codec::{decode_u8_items, encode_u8_items, CodecError, Decode, Encode};
use std::{fmt::Debug, io::Cursor};

/// Defines all parameters necessary to configure an aggregator with a new task.
/// Provided by taskprov participants in all requests incident to task execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskConfig {
    /// Opaque info specific for a task.
    task_info: Vec<u8>,
    /// Leader DAP API endpoint.
    leader_aggregator_endpoint: Url,
    /// Helper DAP API endpoint.
    helper_aggregator_endpoint: Url,
    /// Determines the properties that all batches for this task must have.
    query_config: QueryConfig,
    /// Time up to which Clients are expected to upload to this task.
    task_expiration: Time,
    /// Determines VDAF type and all properties.
    vdaf_config: VdafConfig,
}

impl TaskConfig {
    pub fn new(
        task_info: Vec<u8>,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        query_config: QueryConfig,
        task_expiration: Time,
        vdaf_config: VdafConfig,
    ) -> Result<Self, Error> {
        if task_info.is_empty() {
            return Err(Error::InvalidParameter("task_info must not be empty"));
        }

        Ok(Self {
            task_info,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            query_config,
            task_expiration,
            vdaf_config,
        })
    }

    pub fn task_info(&self) -> &[u8] {
        self.task_info.as_ref()
    }

    pub fn leader_aggregator_endpoint(&self) -> &Url {
        &self.leader_aggregator_endpoint
    }

    pub fn helper_aggregator_endpoint(&self) -> &Url {
        &self.helper_aggregator_endpoint
    }

    pub fn query_config(&self) -> &QueryConfig {
        &self.query_config
    }

    pub fn task_expiration(&self) -> &Time {
        &self.task_expiration
    }

    pub fn vdaf_config(&self) -> &VdafConfig {
        &self.vdaf_config
    }
}

impl Encode for TaskConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_u8_items(bytes, &(), &self.task_info)?;
        self.leader_aggregator_endpoint.encode(bytes)?;
        self.helper_aggregator_endpoint.encode(bytes)?;
        self.query_config.encode(bytes)?;
        self.task_expiration.encode(bytes)?;
        self.vdaf_config.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            (1 + self.task_info.len())
                + self.leader_aggregator_endpoint.encoded_len()?
                + self.helper_aggregator_endpoint.encoded_len()?
                + self.query_config.encoded_len()?
                + self.task_expiration.encoded_len()?
                + self.vdaf_config.encoded_len()?,
        )
    }
}

impl Decode for TaskConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_info = decode_u8_items(&(), bytes)?;
        if task_info.is_empty() {
            return Err(CodecError::Other(
                anyhow!("task_info must not be empty").into(),
            ));
        }

        Ok(Self {
            task_info,
            leader_aggregator_endpoint: Url::decode(bytes)?,
            helper_aggregator_endpoint: Url::decode(bytes)?,
            query_config: QueryConfig::decode(bytes)?,
            task_expiration: Time::decode(bytes)?,
            vdaf_config: VdafConfig::decode(bytes)?,
        })
    }
}

/// All properties that batches for a task must have. Properties are as defined
/// in DAP[1].
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-05.html#name-queries
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryConfig {
    /// Used by clients to truncate report timestamps.
    time_precision: Duration,
    /// The maximum number of times a batch of reports may be queried by the
    /// collector
    max_batch_query_count: u16,
    /// The smallest number of reports that a batch can include.
    min_batch_size: u32,
    /// The query type along with associated parameters.
    query: Query,
}

impl QueryConfig {
    pub fn new(
        time_precision: Duration,
        max_batch_query_count: u16,
        min_batch_size: u32,
        query: Query,
    ) -> Self {
        Self {
            time_precision,
            max_batch_query_count,
            min_batch_size,
            query,
        }
    }

    pub fn time_precision(&self) -> &Duration {
        &self.time_precision
    }

    pub fn max_batch_query_count(&self) -> u16 {
        self.max_batch_query_count
    }

    pub fn min_batch_size(&self) -> u32 {
        self.min_batch_size
    }

    pub fn query(&self) -> &Query {
        &self.query
    }
}

impl Encode for QueryConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self.query {
            Query::Reserved => Query::RESERVED.encode(bytes)?,
            Query::TimeInterval => Query::TIME_INTERVAL.encode(bytes)?,
            Query::FixedSize { .. } => Query::FIXED_SIZE.encode(bytes)?,
        };
        self.time_precision.encode(bytes)?;
        self.max_batch_query_count.encode(bytes)?;
        self.min_batch_size.encode(bytes)?;
        self.query.query_type_param_len().encode(bytes)?;
        if let Query::FixedSize { max_batch_size } = self.query {
            max_batch_size.encode(bytes)?;
        }

        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            1 + self.time_precision.encoded_len()?
                + self.max_batch_query_count.encoded_len()?
                + self.min_batch_size.encoded_len()?
                + 2 // query_type_param_len
                + match self.query {
                    Query::FixedSize { max_batch_size } => max_batch_size.encoded_len()?,
                    _ => 0,
                },
        )
    }
}

impl Decode for QueryConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let query_type = u8::decode(bytes)?;
        let time_precision = Duration::decode(bytes)?;
        let max_batch_query_count = u16::decode(bytes)?;
        let min_batch_size = u32::decode(bytes)?;

        let query_type_param_len = u16::decode(bytes)?;
        let query = match query_type {
            Query::RESERVED => Query::Reserved,
            Query::TIME_INTERVAL => Query::TimeInterval,
            Query::FIXED_SIZE => Query::FixedSize {
                max_batch_size: u32::decode(bytes)?,
            },
            val => {
                return Err(CodecError::Other(
                    anyhow!("unexpected QueryType value {}", val).into(),
                ))
            }
        };
        if query_type_param_len != query.query_type_param_len() {
            return Err(CodecError::Other(
                anyhow!(
                    "unexpected query_type_param_len value {} (wanted {})",
                    query_type_param_len,
                    query.query_type_param_len()
                )
                .into(),
            ));
        }

        Ok(Self {
            time_precision,
            max_batch_query_count,
            min_batch_size,
            query,
        })
    }
}

/// A query type and its associated parameter(s).
///
/// The redefinition of Query relative to the parent mod is for two reasons:
///   - The type of Query is not known at compile time. For queries of unknown
///     type, using the parent mod would require decoding it for each query
///     type until success.
///   - The parent mod decoding logic assumes that the query type is encoded
///     directly adjacent to its associated parameters. This is not the case
///     in taskprov.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Query {
    Reserved,
    TimeInterval,
    FixedSize { max_batch_size: u32 },
}

impl Query {
    const RESERVED: u8 = 0;
    const TIME_INTERVAL: u8 = 1;
    const FIXED_SIZE: u8 = 2;

    fn query_type_param_len(&self) -> u16 {
        match self {
            Self::Reserved | Self::TimeInterval => 0,
            Self::FixedSize { .. } => 4,
        }
    }
}

/// Describes all VDAF parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdafConfig {
    dp_config: DpConfig,
    vdaf_type: VdafType,
}

impl VdafConfig {
    pub fn new(dp_config: DpConfig, vdaf_type: VdafType) -> Result<Self, Error> {
        Ok(Self {
            dp_config,
            vdaf_type,
        })
    }

    pub fn dp_config(&self) -> DpConfig {
        self.dp_config
    }

    pub fn vdaf_type(&self) -> &VdafType {
        &self.vdaf_type
    }
}

impl Encode for VdafConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.dp_config.encode(bytes)?;
        self.vdaf_type.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.dp_config.encoded_len()? + self.vdaf_type.encoded_len()?)
    }
}

impl Decode for VdafConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let ret = Self {
            dp_config: DpConfig::decode(bytes)?,
            vdaf_type: VdafType::decode(bytes)?,
        };
        Ok(ret)
    }
}

#[derive(Clone, PartialEq, Eq, Derivative)]
#[derivative(Debug)]
#[repr(u32)]
#[non_exhaustive]
pub enum VdafType {
    Prio3Count,
    Prio3Sum {
        /// Bit length of the summand.
        bits: u8,
    },
    Prio3SumVec {
        /// Bit length of each summand.
        bits: u8,
        /// Number of summands.
        length: u32,
        /// Size of each proof chunk.
        chunk_length: u32,
    },
    Prio3Histogram {
        /// Number of buckets.
        length: u32,
        /// Size of each proof chunk.
        chunk_length: u32,
    },
    Poplar1 {
        /// Bit length of the input string.
        bits: u16,
    },
}

impl VdafType {
    const PRIO3COUNT: u32 = 0x00000000;
    const PRIO3SUM: u32 = 0x00000001;
    const PRIO3SUMVEC: u32 = 0x00000002;
    const PRIO3HISTOGRAM: u32 = 0x00000003;
    const POPLAR1: u32 = 0x00001000;

    fn vdaf_type_code(&self) -> u32 {
        match self {
            Self::Prio3Count => Self::PRIO3COUNT,
            Self::Prio3Sum { .. } => Self::PRIO3SUM,
            Self::Prio3SumVec { .. } => Self::PRIO3SUMVEC,
            Self::Prio3Histogram { .. } => Self::PRIO3HISTOGRAM,
            Self::Poplar1 { .. } => Self::POPLAR1,
        }
    }

    fn vdaf_type_param_len(&self) -> u16 {
        match self {
            Self::Prio3Count => 0,
            Self::Prio3Sum { .. } => 1,
            Self::Prio3SumVec { .. } => 9,
            Self::Prio3Histogram { .. } => 8,
            Self::Poplar1 { .. } => 2,
        }
    }
}

impl Encode for VdafType {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.vdaf_type_code().encode(bytes)?;
        self.vdaf_type_param_len().encode(bytes)?;

        match self {
            Self::Prio3Count => (),
            Self::Prio3Sum { bits } => {
                bits.encode(bytes)?;
            }
            Self::Prio3SumVec {
                bits,
                length,
                chunk_length,
            } => {
                bits.encode(bytes)?;
                length.encode(bytes)?;
                chunk_length.encode(bytes)?;
            }
            Self::Prio3Histogram {
                length,
                chunk_length,
            } => {
                length.encode(bytes)?;
                chunk_length.encode(bytes)?;
            }
            Self::Poplar1 { bits } => {
                bits.encode(bytes)?;
            }
        }
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            4 + 2
                + match self {
                    Self::Prio3Count => 0,
                    Self::Prio3Sum { .. } => 1,
                    Self::Prio3SumVec { .. } => 9,
                    Self::Prio3Histogram { .. } => 8,
                    Self::Poplar1 { .. } => 2,
                },
        )
    }
}

impl Decode for VdafType {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let vdaf_type_code = u32::decode(bytes)?;
        let vdaf_type_param_len = u16::decode(bytes)?;

        let vdaf_type = match vdaf_type_code {
            Self::PRIO3COUNT => Self::Prio3Count,
            Self::PRIO3SUM => Self::Prio3Sum {
                bits: u8::decode(bytes)?,
            },
            Self::PRIO3SUMVEC => Self::Prio3SumVec {
                bits: u8::decode(bytes)?,
                length: u32::decode(bytes)?,
                chunk_length: u32::decode(bytes)?,
            },
            Self::PRIO3HISTOGRAM => Self::Prio3Histogram {
                length: u32::decode(bytes)?,
                chunk_length: u32::decode(bytes)?,
            },
            Self::POPLAR1 => Self::Poplar1 {
                bits: u16::decode(bytes)?,
            },
            val => {
                return Err(CodecError::Other(
                    anyhow!("unexpected VDAF type code value {}", val).into(),
                ))
            }
        };

        if vdaf_type_param_len != vdaf_type.vdaf_type_param_len() {
            return Err(CodecError::Other(
                anyhow!(
                    "unexpected vdaf_type_param_len value {} (wanted {})",
                    vdaf_type_param_len,
                    vdaf_type.vdaf_type_param_len()
                )
                .into(),
            ));
        }

        Ok(vdaf_type)
    }
}

/// Parameters for Differential Privacy. This is mostly unspecified at the moment.
/// See [draft-irtf-cfrg-vdaf/#94][1] for discussion.
///
/// [1]: https://github.com/cfrg/draft-irtf-cfrg-vdaf/issues/94
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpConfig {
    dp_mechanism: DpMechanism,
}

impl DpConfig {
    pub fn new(dp_mechanism: DpMechanism) -> Self {
        Self { dp_mechanism }
    }

    pub fn dp_mechanism(&self) -> &DpMechanism {
        &self.dp_mechanism
    }
}

impl Encode for DpConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.dp_mechanism.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        self.dp_mechanism.encoded_len()
    }
}

impl Decode for DpConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self {
            dp_mechanism: DpMechanism::decode(bytes)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum DpMechanism {
    Reserved,
    None,
}

impl DpMechanism {
    const RESERVED: u8 = 0;
    const NONE: u8 = 1;

    fn dp_mechanism_param_len(&self) -> u16 {
        0
    }
}

impl Encode for DpMechanism {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            Self::Reserved => Self::RESERVED.encode(bytes)?,
            Self::None => Self::NONE.encode(bytes)?,
        };
        self.dp_mechanism_param_len().encode(bytes)?;
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        match self {
            Self::Reserved | Self::None => Some(3),
        }
    }
}

impl Decode for DpMechanism {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let dp_mechanism_code = u8::decode(bytes)?;
        let dp_mechanism_param_len = u16::decode(bytes)?;
        let dp_mechanism = match dp_mechanism_code {
            Self::RESERVED => Self::Reserved,
            Self::NONE => Self::None,
            val => {
                return Err(CodecError::Other(
                    anyhow!("unexpected DpMechanism value {}", val).into(),
                ))
            }
        };

        if dp_mechanism_param_len != dp_mechanism.dp_mechanism_param_len() {
            return Err(CodecError::Other(
                anyhow!(
                    "unexpected dp_mechanism_param_len value {} (wanted {})",
                    dp_mechanism_param_len,
                    dp_mechanism.dp_mechanism_param_len()
                )
                .into(),
            ));
        }

        Ok(dp_mechanism)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roundtrip_encoding;
    use assert_matches::assert_matches;

    #[test]
    fn roundtrip_dp_config() {
        roundtrip_encoding(&[
            (
                DpConfig::new(DpMechanism::Reserved),
                concat!(
                    "00",   // dp_mechanism
                    "0000", // dp_mechanism_param_len
                ),
            ),
            (
                DpConfig::new(DpMechanism::None),
                concat!(
                    "01",   // dp_mechanism
                    "0000", // dp_mechanism_param_len
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_vdaf_type() {
        roundtrip_encoding(&[
            (
                VdafType::Prio3Count,
                concat!(
                    "00000000", // vdaf_type_code
                    "0000",     // vdaf_type_param_len
                ),
            ),
            (
                VdafType::Prio3Sum { bits: u8::MIN },
                concat!(
                    "00000001", // vdaf_type_code
                    "0001",     // vdaf_type_param_len
                    "00"        // bits
                ),
            ),
            (
                VdafType::Prio3Sum { bits: 0x80 },
                concat!(
                    "00000001", // vdaf_type_code
                    "0001",     // vdaf_type_param_len
                    "80"        // bits
                ),
            ),
            (
                VdafType::Prio3Sum { bits: u8::MAX },
                concat!(
                    "00000001", // vdaf_type_code
                    "0001",     // vdaf_type_param_len
                    "FF",       // bits
                ),
            ),
            (
                VdafType::Prio3SumVec {
                    bits: 8,
                    length: 12,
                    chunk_length: 14,
                },
                concat!(
                    "00000002", // vdaf_type_code
                    "0009",     // vdaf_type_param_len
                    "08",       // bits
                    "0000000C", // length
                    "0000000E"  // chunk_length
                ),
            ),
            (
                VdafType::Prio3Histogram {
                    length: 256,
                    chunk_length: 18,
                },
                concat!(
                    "00000003", // vdaf_type_code
                    "0008",     // vdaf_type_param_len
                    "00000100", // length
                    "00000012", // chunk_length
                ),
            ),
            (
                VdafType::Poplar1 { bits: u16::MIN },
                concat!(
                    "00001000", // vdaf_type_code
                    "0002",     // vdaf_type_param_len
                    "0000",     // bits
                ),
            ),
            (
                VdafType::Poplar1 { bits: 0xABAB },
                concat!(
                    "00001000", // vdaf_type_code
                    "0002",     // vdaf_type_param_len
                    "ABAB",     // bits
                ),
            ),
            (
                VdafType::Poplar1 { bits: u16::MAX },
                concat!(
                    "00001000", // vdaf_type_code
                    "0002",     // vdaf_type_param_len
                    "FFFF"      // bits
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_vdaf_config() {
        roundtrip_encoding(&[
            (
                VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Count).unwrap(),
                concat!(
                    concat!(
                        // dp_config
                        "01",   // dp_mechanism
                        "0000", // dp_mechanism_param_len
                    ),
                    concat!(
                        // vdaf_type
                        "00000000", // vdaf_type_code
                        "0000",     // vdaf_type_param_len
                    ),
                ),
            ),
            (
                VdafConfig::new(
                    DpConfig::new(DpMechanism::None),
                    VdafType::Prio3Sum { bits: 0x42 },
                )
                .unwrap(),
                concat!(
                    concat!(
                        // dp_config
                        "01",   // dp_mechanism
                        "0000", // dp_mechanism_param_len
                    ),
                    concat!(
                        // vdaf_type
                        "00000001", // vdaf_type_code
                        "0001",     // vdaf_type_param_len
                        "42",       // bits
                    ),
                ),
            ),
            (
                VdafConfig::new(
                    DpConfig::new(DpMechanism::None),
                    VdafType::Prio3SumVec {
                        bits: 8,
                        length: 12,
                        chunk_length: 14,
                    },
                )
                .unwrap(),
                concat!(
                    concat!(
                        // dp_config
                        "01",   // dp_mechanism
                        "0000", // dp_mechanism_param_len
                    ),
                    concat!(
                        // vdaf_type
                        "00000002", // vdaf_type_code
                        "0009",     // vdaf_type_param_len
                        "08",       // bits
                        "0000000C", // length
                        "0000000E", // chunk_length
                    )
                ),
            ),
            (
                VdafConfig::new(
                    DpConfig::new(DpMechanism::None),
                    VdafType::Prio3Histogram {
                        length: 10,
                        chunk_length: 4,
                    },
                )
                .unwrap(),
                concat!(
                    concat!(
                        // dp_config
                        "01",   // dp_mechanism
                        "0000", // dp_mechanism_param_len
                    ),
                    concat!(
                        // vdaf_type
                        "00000003", // vdaf_type_code
                        "0008",     // vdaf_type_param_len
                        "0000000A", // length
                        "00000004", // chunk_length
                    ),
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_query_config() {
        roundtrip_encoding(&[
            (
                QueryConfig::new(
                    Duration::from_seconds(0x3C),
                    0x40,
                    0x24,
                    Query::TimeInterval,
                ),
                concat!(
                    "01",               // query_type
                    "000000000000003C", // time_precision
                    "0040",             // max_batch_query_count
                    "00000024",         // min_batch_size
                    "0000",             // query_type_param_len
                ),
            ),
            (
                QueryConfig::new(
                    Duration::from_seconds(u64::MIN),
                    u16::MIN,
                    u32::MIN,
                    Query::FixedSize {
                        max_batch_size: u32::MIN,
                    },
                ),
                concat!(
                    "02",               // query_type
                    "0000000000000000", // time_precision
                    "0000",             // max_batch_query_count
                    "00000000",         // min_batch_size
                    "0004",             // query_type_param_len
                    "00000000",         // max_batch_size
                ),
            ),
            (
                QueryConfig::new(
                    Duration::from_seconds(0x3C),
                    0x40,
                    0x24,
                    Query::FixedSize {
                        max_batch_size: 0xFAFA,
                    },
                ),
                concat!(
                    "02",               // query_type
                    "000000000000003C", // time_precision
                    "0040",             // max_batch_query_count
                    "00000024",         // min_batch_size
                    "0004",             // query_type_param_len
                    "0000FAFA",         // max_batch_size
                ),
            ),
            (
                QueryConfig::new(
                    Duration::from_seconds(u64::MAX),
                    u16::MAX,
                    u32::MAX,
                    Query::FixedSize {
                        max_batch_size: u32::MAX,
                    },
                ),
                concat!(
                    "02",               // query_type
                    "FFFFFFFFFFFFFFFF", // time_precision
                    "FFFF",             // max_batch_query_count
                    "FFFFFFFF",         // min_batch_size
                    "0004",             // query_type_param_len
                    "FFFFFFFF",         // max_batch_size
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_task_config() {
        roundtrip_encoding(&[
            (
                TaskConfig::new(
                    "foobar".as_bytes().to_vec(),
                    Url::try_from("https://example.com/".as_ref()).unwrap(),
                    Url::try_from("https://another.example.com/".as_ref()).unwrap(),
                    QueryConfig::new(
                        Duration::from_seconds(0xAAAA),
                        0xBBBB,
                        0xCCCC,
                        Query::FixedSize {
                            max_batch_size: 0xDDDD,
                        },
                    ),
                    Time::from_seconds_since_epoch(0xEEEE),
                    VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Count)
                        .unwrap(),
                )
                .unwrap(),
                concat!(
                    concat!(
                        // task_info
                        "06",           // length
                        "666F6F626172"  // opaque data
                    ),
                    concat!(
                        // leader_aggregator_url
                        "0014",                                     // length
                        "68747470733A2F2F6578616D706C652E636F6D2F"  // contents
                    ),
                    concat!(
                        // helper_aggregator_url
                        "001C",                                                     // length
                        "68747470733A2F2F616E6F746865722E6578616D706C652E636F6D2F"  // contents
                    ),
                    concat!(
                        // query_config
                        "02",               // query_type
                        "000000000000AAAA", // time_precision
                        "BBBB",             // max_batch_query_count
                        "0000CCCC",         // min_batch_size
                        "0004",             // query_type_param_len
                        "0000DDDD",         // max_batch_size
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        concat!(
                            // dp_config
                            "01",   // dp_config
                            "0000", // dp_mechanism_param_len
                        ),
                        concat!(
                            // vdaf_type
                            "00000000", // vdaf_type_code
                            "0000",     // vdaf_type_param_len
                        ),
                    ),
                ),
            ),
            (
                TaskConfig::new(
                    "f".as_bytes().to_vec(),
                    Url::try_from("https://example.com/".as_ref()).unwrap(),
                    Url::try_from("https://another.example.com/".as_ref()).unwrap(),
                    QueryConfig::new(
                        Duration::from_seconds(0xAAAA),
                        0xBBBB,
                        0xCCCC,
                        Query::TimeInterval,
                    ),
                    Time::from_seconds_since_epoch(0xEEEE),
                    VdafConfig::new(
                        DpConfig::new(DpMechanism::None),
                        VdafType::Prio3Histogram {
                            length: 10,
                            chunk_length: 4,
                        },
                    )
                    .unwrap(),
                )
                .unwrap(),
                concat!(
                    concat!(
                        // task_info
                        "01", // length
                        "66"  // opaque data
                    ),
                    concat!(
                        // leader_aggregator_url
                        "0014",                                     // length
                        "68747470733A2F2F6578616D706C652E636F6D2F"  // contents
                    ),
                    concat!(
                        // helper_aggregator_url
                        "001C",                                                     // length
                        "68747470733A2F2F616E6F746865722E6578616D706C652E636F6D2F"  // contents
                    ),
                    concat!(
                        // query_config
                        "01",               // query_type
                        "000000000000AAAA", // time_precision
                        "BBBB",             // max_batch_query_count
                        "0000CCCC",         // min_batch_size
                        "0000",             // query_type_param_len
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        concat!(
                            // dp_config
                            "01",   // dp_mechanism
                            "0000", // dp_mechanism_param_len
                        ),
                        concat!(
                            // vdaf_type
                            "00000003", // vdaf_type_code
                            "0008",     // vdaf_type_param_len
                            "0000000A", // length
                            "00000004", // chunk_length
                        ),
                    ),
                ),
            ),
        ]);

        // Empty task_info.
        assert_matches!(
            TaskConfig::get_decoded(
                &hex::decode(concat!(
                    concat!(
                        // task_info
                        "00", // length
                    ),
                    concat!(
                        // leader_aggregator_url
                        "0014",                                     // length
                        "68747470733A2F2F6578616D706C652E636F6D2F"  // contents
                    ),
                    concat!(
                        // helper_aggregator_url
                        "001C",                                                     // length
                        "68747470733A2F2F616E6F746865722E6578616D706C652E636F6D2F"  // contents
                    ),
                    concat!(
                        // query_config
                        "01",               // query_type
                        "000000000000AAAA", // time_precision
                        "BBBB",             // max_batch_query_count
                        "0000CCCC",         // min_batch_size
                        "0000",             // query_type_param_len
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        concat!(
                            // dp_config
                            "01",   // dp_config
                            "0000", // dp_mechanism_param_len
                        ),
                        concat!(
                            // vdaf_type
                            "00000000", // vdaf_type_code
                            "0000",     // vdaf_type_param_len
                        ),
                    ),
                ))
                .unwrap(),
            ),
            Err(CodecError::Other(_))
        );
    }
}
