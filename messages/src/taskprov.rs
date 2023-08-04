//! Data structures as defined in extension [draft-wang-ppm-dap-taskprov][1].
//!
//! [1]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/

use crate::{Duration, Error, Role, Time, Url};
use anyhow::anyhow;
use derivative::Derivative;
use prio::codec::{
    decode_u16_items, decode_u24_items, decode_u8_items, encode_u16_items, encode_u24_items,
    encode_u8_items, CodecError, Decode, Encode,
};
use std::{
    fmt::{self, Debug, Formatter},
    io::Cursor,
};

/// Defines all parameters necessary to configure an aggregator with a new task.
/// Provided by taskprov participants in all requests incident to task execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskConfig {
    /// Opaque info specific for a task.
    task_info: Vec<u8>,
    /// List of URLs where the aggregator's API endpoints can be found.
    aggregator_endpoints: Vec<Url>,
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
        aggregator_endpoints: Vec<Url>,
        query_config: QueryConfig,
        task_expiration: Time,
        vdaf_config: VdafConfig,
    ) -> Result<Self, Error> {
        if task_info.is_empty() {
            Err(Error::InvalidParameter("task_info must not be empty"))
        } else if aggregator_endpoints.is_empty() {
            Err(Error::InvalidParameter(
                "aggregator_endpoints must not be empty",
            ))
        } else {
            Ok(Self {
                task_info,
                aggregator_endpoints,
                query_config,
                task_expiration,
                vdaf_config,
            })
        }
    }

    pub fn task_info(&self) -> &[u8] {
        self.task_info.as_ref()
    }

    pub fn aggregator_endpoints(&self) -> &[Url] {
        self.aggregator_endpoints.as_ref()
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

    /// Returns the [`Url`] relative to which the server performing `role` serves its API.
    pub fn aggregator_url(&self, role: &Role) -> Result<&Url, Error> {
        let index = role.index().ok_or(Error::InvalidParameter(role.as_str()))?;
        Ok(&self.aggregator_endpoints[index])
    }
}

impl Encode for TaskConfig {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u8_items(bytes, &(), &self.task_info);
        encode_u16_items(bytes, &(), &self.aggregator_endpoints);
        self.query_config.encode(bytes);
        self.task_expiration.encode(bytes);
        self.vdaf_config.encode(bytes);
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            (1 + self.task_info.len())
                + (2 + self
                    .aggregator_endpoints
                    .iter()
                    // Unwrap safety: url.encoded_len() always returns Some.
                    .fold(0, |acc, url| acc + url.encoded_len().unwrap()))
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

        let aggregator_endpoints = decode_u16_items(&(), bytes)?;
        if aggregator_endpoints.is_empty() {
            return Err(CodecError::Other(
                anyhow!("aggregator_endpoints must not be empty").into(),
            ));
        }

        Ok(Self {
            task_info,
            aggregator_endpoints,
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
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self.query {
            Query::Reserved => Query::RESERVED.encode(bytes),
            Query::TimeInterval => Query::TIME_INTERVAL.encode(bytes),
            Query::FixedSize { .. } => Query::FIXED_SIZE.encode(bytes),
        };
        self.time_precision.encode(bytes);
        self.max_batch_query_count.encode(bytes);
        self.min_batch_size.encode(bytes);
        if let Query::FixedSize { max_batch_size } = self.query {
            max_batch_size.encode(bytes)
        }
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            1 + self.time_precision.encoded_len()?
                + self.max_batch_query_count.encoded_len()?
                + self.min_batch_size.encoded_len()?
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
        Ok(Self {
            time_precision: Duration::decode(bytes)?,
            max_batch_query_count: u16::decode(bytes)?,
            min_batch_size: u32::decode(bytes)?,
            query: match query_type {
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
            },
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
///
/// The redefinition of [`aggregator_core::task::QueryType`] is because the
/// two types are subtly incompatible (presence of Reserved, size of
/// max_batch_size).
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
}

/// Describes all VDAF parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdafConfig {
    dp_config: DpConfig,
    vdaf_type: VdafType,
}

impl VdafConfig {
    pub fn new(dp_config: DpConfig, vdaf_type: VdafType) -> Result<Self, Error> {
        if let VdafType::Prio3Histogram { buckets } = &vdaf_type {
            if buckets.is_empty() {
                return Err(Error::InvalidParameter(
                    "buckets must not be empty for Prio3Histogram",
                ));
            }
        }
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
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.dp_config.encode(bytes);
        self.vdaf_type.encode(bytes);
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
        if let VdafType::Prio3Histogram { buckets } = &ret.vdaf_type {
            if buckets.is_empty() {
                return Err(CodecError::Other(
                    anyhow!("buckets must not be empty for Prio3Histogram").into(),
                ));
            }
        }
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
    Prio3Histogram {
        /// List of buckets.
        #[derivative(Debug(format_with = "fmt_histogram"))]
        buckets: Vec<u64>,
    },
    Poplar1 {
        /// Bit length of the input string.
        bits: u16,
    },
}

impl VdafType {
    const PRIO3COUNT: u32 = 0x00000000;
    const PRIO3SUM: u32 = 0x00000001;
    const PRIO3HISTOGRAM: u32 = 0x00000002;
    const POPLAR1: u32 = 0x00001000;
}

fn fmt_histogram(buckets: &Vec<u64>, f: &mut Formatter) -> Result<(), fmt::Error> {
    write!(f, "num_buckets: {}", buckets.len())
}

impl Encode for VdafType {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Prio3Count => Self::PRIO3COUNT.encode(bytes),
            Self::Prio3Sum { bits } => {
                Self::PRIO3SUM.encode(bytes);
                bits.encode(bytes);
            }
            Self::Prio3Histogram { buckets } => {
                Self::PRIO3HISTOGRAM.encode(bytes);
                encode_u24_items(bytes, &(), buckets);
            }
            Self::Poplar1 { bits } => {
                Self::POPLAR1.encode(bytes);
                bits.encode(bytes);
            }
        }
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(
            4 + match self {
                Self::Prio3Count => 0,
                Self::Prio3Sum { bits } => bits.encoded_len()?,
                Self::Prio3Histogram { buckets } => 3 + buckets.len() * 0u64.encoded_len()?,
                Self::Poplar1 { bits } => bits.encoded_len()?,
            },
        )
    }
}

impl Decode for VdafType {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u32::decode(bytes)? {
            Self::PRIO3COUNT => Ok(Self::Prio3Count),
            Self::PRIO3SUM => Ok(Self::Prio3Sum {
                bits: u8::decode(bytes)?,
            }),
            Self::PRIO3HISTOGRAM => Ok(Self::Prio3Histogram {
                buckets: decode_u24_items(&(), bytes)?,
            }),
            Self::POPLAR1 => Ok(Self::Poplar1 {
                bits: u16::decode(bytes)?,
            }),
            val => Err(CodecError::Other(
                anyhow!("unexpected Self value {}", val).into(),
            )),
        }
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
    fn encode(&self, bytes: &mut Vec<u8>) {
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
}

impl Encode for DpMechanism {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Reserved => Self::RESERVED.encode(bytes),
            Self::None => Self::NONE.encode(bytes),
        }
    }

    fn encoded_len(&self) -> Option<usize> {
        match self {
            Self::Reserved | Self::None => Some(1),
        }
    }
}

impl Decode for DpMechanism {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        match u8::decode(bytes)? {
            Self::RESERVED => Ok(Self::Reserved),
            Self::NONE => Ok(Self::None),
            val => Err(CodecError::Other(
                anyhow!("unexpected DpMechanism value {}", val).into(),
            )),
        }
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
            (DpConfig::new(DpMechanism::Reserved), "00"),
            (DpConfig::new(DpMechanism::None), "01"),
        ])
    }

    #[test]
    fn roundtrip_vdaf_type() {
        roundtrip_encoding(&[
            (VdafType::Prio3Count, "00000000"),
            (
                VdafType::Prio3Sum { bits: u8::MIN },
                concat!("00000001", "00"),
            ),
            (VdafType::Prio3Sum { bits: 0x80 }, concat!("00000001", "80")),
            (
                VdafType::Prio3Sum { bits: u8::MAX },
                concat!("00000001", "FF"),
            ),
            (
                VdafType::Prio3Histogram {
                    buckets: vec![0x00ABCDEF, 0x40404040, 0xDEADBEEF],
                },
                concat!(
                    "00000002",
                    "000018", // length
                    "0000000000ABCDEF",
                    "0000000040404040",
                    "00000000DEADBEEF",
                ),
            ),
            (
                VdafType::Prio3Histogram {
                    buckets: vec![u64::MIN, u64::MAX],
                },
                concat!(
                    "00000002",
                    "000010", // length
                    "0000000000000000",
                    "FFFFFFFFFFFFFFFF",
                ),
            ),
            (
                VdafType::Poplar1 { bits: u16::MIN },
                concat!("00001000", "0000"),
            ),
            (
                VdafType::Poplar1 { bits: 0xABAB },
                concat!("00001000", "ABAB"),
            ),
            (
                VdafType::Poplar1 { bits: u16::MAX },
                concat!("00001000", "FFFF"),
            ),
        ])
    }

    #[test]
    fn roundtrip_vdaf_config() {
        roundtrip_encoding(&[
            (
                VdafConfig::new(DpConfig::new(DpMechanism::None), VdafType::Prio3Count).unwrap(),
                concat!("01", "00000000"),
            ),
            (
                VdafConfig::new(
                    DpConfig::new(DpMechanism::None),
                    VdafType::Prio3Sum { bits: 0x42 },
                )
                .unwrap(),
                concat!("01", concat!("00000001", "42")),
            ),
            (
                VdafConfig::new(
                    DpConfig::new(DpMechanism::None),
                    VdafType::Prio3Histogram {
                        buckets: vec![0xAAAAAAAA],
                    },
                )
                .unwrap(),
                concat!("01", concat!("00000002", "000008", "00000000AAAAAAAA")),
            ),
        ]);

        // Empty Prio3Histogram buckets.
        assert_matches!(
            VdafConfig::get_decoded(
                &hex::decode(concat!("01", concat!("00000002", "000000"))).unwrap()
            ),
            Err(CodecError::Other(_))
        );
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
                    "01",               // query type
                    "000000000000003C", // time precision
                    "0040",             // max batch query count
                    "00000024",         // min batch size
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
                    "02",               // query type
                    "0000000000000000", // time precision
                    "0000",             // max batch query count
                    "00000000",         // min batch size
                    "00000000",         // max batch size
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
                    "02",               // query type
                    "000000000000003C", // time precision
                    "0040",             // max batch query count
                    "00000024",         // min batch size
                    "0000FAFA",         // max batch size
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
                    "02",               // query type
                    "FFFFFFFFFFFFFFFF", // time precision
                    "FFFF",             // max batch query count
                    "FFFFFFFF",         // min batch size
                    "FFFFFFFF",         // max batch size
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
                    vec![
                        Url::try_from("https://example.com/".as_ref()).unwrap(),
                        Url::try_from("https://another.example.com/".as_ref()).unwrap(),
                    ],
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
                        // aggregator_endpoints
                        "0034", // length of all vector contents
                        concat!(
                            "0014",                                     // length
                            "68747470733A2F2F6578616D706C652E636F6D2F"  // contents
                        ),
                        concat!(
                            "001C",                                                     // length
                            "68747470733A2F2F616E6F746865722E6578616D706C652E636F6D2F"  // contents
                        ),
                    ),
                    concat!(
                        // query_config
                        "02",               // query type
                        "000000000000AAAA", // time precision
                        "BBBB",             // max batch query count
                        "0000CCCC",         // min batch size
                        "0000DDDD",         // max batch size
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        "01",       // dp_config
                        "00000000", // vdaf_type
                    ),
                ),
            ),
            (
                TaskConfig::new(
                    "f".as_bytes().to_vec(),
                    vec![Url::try_from("https://example.com".as_ref()).unwrap()],
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
                            buckets: vec![0xFFFF],
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
                        // aggregator_endpoints
                        "0015", // length of all vector contents
                        concat!(
                            "0013",                                   // length
                            "68747470733A2F2F6578616D706C652E636F6D"  // contents
                        ),
                    ),
                    concat!(
                        // query_config
                        "01",               // query type
                        "000000000000AAAA", // time precision
                        "BBBB",             // max batch query count
                        "0000CCCC",         // min batch size
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        "01",       // dp_config
                        "00000002", // vdaf_type
                        concat!(
                            // buckets
                            "000008",           // length
                            "000000000000FFFF"  // bucket
                        )
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
                        // aggregator_endpoints
                        "0003", // length of all vector contents
                        concat!(
                            "0001", // length
                            "68"    // contents
                        ),
                    ),
                    concat!(
                        // query_config
                        "01",               // query type
                        "000000000000AAAA", // time precision
                        "BBBB",             // max batch query count
                        "0000CCCC",         // min batch size
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        "01",       // dp_config
                        "00000002", // vdaf_type
                        concat!(
                            // buckets
                            "000008",           // length
                            "000000000000FFFF"  // bucket
                        )
                    ),
                ))
                .unwrap(),
            ),
            Err(CodecError::Other(_))
        );

        // Empty aggregator_urls
        assert_matches!(
            TaskConfig::get_decoded(
                &hex::decode(concat!(
                    concat!(
                        // task_info
                        "01", // length
                        "66"  // opaque data
                    ),
                    concat!(
                        // aggregator_endpoints
                        "0000", // length of all vector contents
                    ),
                    concat!(
                        // query_config
                        "01",               // query type
                        "000000000000AAAA", // time precision
                        "BBBB",             // max batch query count
                        "0000CCCC",         // min batch size
                    ),
                    "000000000000EEEE", // task_expiration
                    concat!(
                        // vdaf_config
                        "01",       // dp_config
                        "00000002", // vdaf_type
                        concat!(
                            // buckets
                            "000008",           // length
                            "000000000000FFFF"  // bucket
                        )
                    ),
                ))
                .unwrap(),
            ),
            Err(CodecError::Other(_))
        );
    }
}
