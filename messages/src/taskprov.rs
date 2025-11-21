//! Data structures as defined in extension [draft-wang-ppm-dap-taskprov][1].
//!
//! [1]: https://datatracker.ietf.org/doc/draft-wang-ppm-dap-taskprov/

use crate::{Duration, Error, Time, Url, batch_mode};
use anyhow::anyhow;
use num_enum::TryFromPrimitive;
use prio::codec::{
    CodecError, Decode, Encode, decode_u8_items, decode_u16_items, encode_u8_items,
    encode_u16_items,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display, Formatter},
    io::Cursor,
};

/// Defines all parameters necessary to configure an aggregator with a new task.
/// Provided by taskprov participants in all requests incident to task execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskConfig {
    /// Opaque info specific for this task.
    task_info: Vec<u8>,
    /// Leader DAP API endpoint.
    leader_aggregator_endpoint: Url,
    /// Helper DAP API endpoint.
    helper_aggregator_endpoint: Url,
    /// Time precision of this task.
    time_precision: TimePrecision,
    /// The minimum batch size for this task.
    min_batch_size: u32,
    /// Determines the batch mode for this task.
    batch_mode: batch_mode::Code,
    /// The earliest timestamp that will be accepted for this task.
    task_start: Time,
    /// The duration of the task.
    task_duration: TimePrecision,
    /// Determines VDAF type and all properties.
    vdaf_config: VdafConfig,
    /// Taskbind extensions.
    extensions: Vec<TaskbindExtension>,
}

impl TaskConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_info: Vec<u8>,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: TimePrecision,
        min_batch_size: u32,
        batch_mode: batch_mode::Code,
        task_start: Time,
        task_duration: TimePrecision,
        vdaf_config: VdafConfig,
        extensions: Vec<TaskbindExtension>,
    ) -> Result<Self, Error> {
        if task_info.is_empty() {
            return Err(Error::InvalidParameter("task_info must not be empty"));
        }

        Ok(Self {
            task_info,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            min_batch_size,
            batch_mode,
            task_start,
            task_duration,
            vdaf_config,
            extensions,
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

    pub fn time_precision(&self) -> &TimePrecision {
        &self.time_precision
    }

    pub fn min_batch_size(&self) -> &u32 {
        &self.min_batch_size
    }

    pub fn batch_mode(&self) -> &batch_mode::Code {
        &self.batch_mode
    }

    pub fn task_start(&self) -> &Time {
        &self.task_start
    }

    pub fn task_duration(&self) -> &TimePrecision {
        &self.task_duration
    }

    pub fn vdaf_config(&self) -> &VdafConfig {
        &self.vdaf_config
    }

    pub fn extensions(&self) -> &[TaskbindExtension] {
        &self.extensions
    }
}

impl Encode for TaskConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_u8_items(bytes, &(), &self.task_info)?;
        self.leader_aggregator_endpoint.encode(bytes)?;
        self.helper_aggregator_endpoint.encode(bytes)?;
        self.time_precision.encode(bytes)?;
        self.min_batch_size.encode(bytes)?;
        self.batch_mode.encode(bytes)?;
        (0u16).encode(bytes)?; // batch_config length (batch_config always empty currently)
        self.task_start.encode(bytes)?;
        self.task_duration.encode(bytes)?;
        self.vdaf_config.encode(bytes)?;
        encode_u16_items(bytes, &(), &self.extensions)?;
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        let mut len = (1 + self.task_info.len())
            + self.leader_aggregator_endpoint.encoded_len()?
            + self.helper_aggregator_endpoint.encoded_len()?
            + self.time_precision.encoded_len()?
            + self.min_batch_size.encoded_len()?
            + (self.batch_mode.encoded_len()? + 2)
            + self.task_start.encoded_len()?
            + self.task_duration.encoded_len()?
            + self.vdaf_config.encoded_len()?;

        // Extensions.
        len += 2;
        for extension in &self.extensions {
            len += extension.encoded_len()?;
        }

        Some(len)
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
        let leader_aggregator_endpoint = Url::decode(bytes)?;
        let helper_aggregator_endpoint = Url::decode(bytes)?;
        let time_precision = TimePrecision::decode(bytes)?;
        let min_batch_size = u32::decode(bytes)?;
        let batch_mode = batch_mode::Code::decode(bytes)?;
        let batch_config_len = u16::decode(bytes)?;
        if batch_config_len != 0 {
            return Err(CodecError::Other(
                anyhow!("batch_config length is not zero").into(),
            ));
        };
        let task_start = Time::decode(bytes)?;
        let task_duration = TimePrecision::decode(bytes)?;
        let vdaf_config = VdafConfig::decode(bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_info,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            min_batch_size,
            batch_mode,
            task_start,
            task_duration,
            vdaf_config,
            extensions,
        })
    }
}

/// Tasprov message indicating a VDAF configuration. This type corresponds to (and encodes/decodes
/// as) a concatenation of the type code, a 2-byte length field, and one of the VdafConfig messages
/// defined in the taskprov specification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VdafConfig {
    // Specified in VDAF/taskprov.
    Reserved,
    Prio3Count,
    Prio3Sum {
        /// Largest summand.
        max_measurement: u32,
    },
    Prio3SumVec {
        /// Length of the vector.
        length: u32,
        /// Bit length of each summand.
        bits: u8,
        /// Size of each proof chunk.
        chunk_length: u32,
    },
    Prio3Histogram {
        /// Number of buckets.
        length: u32,
        /// Size of each proof chunk.
        chunk_length: u32,
    },
    Prio3MultihotCountVec {
        /// Length of the vector.
        length: u32,
        /// Size of each proof chunk.
        chunk_length: u32,
        /// Largest vector weight.
        max_weight: u32,
    },
    Poplar1 {
        /// Bit length of the input string.
        bits: u16,
    },

    // "Reserved for private use" space [0xFFFF0000 - 0xFFFFFFFF]
    /// A fake, no-op VDAF, which uses an aggregation parameter and a variable number of rounds.
    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    Fake {
        rounds: u32,
    },
    Prio3SumVecField64MultiproofHmacSha256Aes128 {
        /// Number of summands.
        length: u32,
        /// Bit length of each summand.
        bits: u8,
        /// Size of each proof chunk.
        chunk_length: u32,
        /// Number of proofs.
        proofs: u8,
    },
}

impl VdafConfig {
    // Specified in VDAF.
    const RESERVED: u32 = 0x00000000;
    const PRIO3_COUNT: u32 = 0x00000001;
    const PRIO3_SUM: u32 = 0x00000002;
    const PRIO3_SUM_VEC: u32 = 0x00000003;
    const PRIO3_HISTOGRAM: u32 = 0x00000004;
    const PRIO3_MULTIHOT_COUNT_VEC: u32 = 0x00000005;
    const POPLAR1: u32 = 0x00000006;

    // "Reserved for private use" space [0xFFFF0000 - 0xFFFFFFFF]
    #[cfg(feature = "test-util")]
    const FAKE: u32 = 0xFFFF0000;
    const PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128: u32 = 0xFFFF1003;

    fn vdaf_type_code(&self) -> u32 {
        match self {
            Self::Reserved => Self::RESERVED,
            Self::Prio3Count => Self::PRIO3_COUNT,
            Self::Prio3Sum { .. } => Self::PRIO3_SUM,
            Self::Prio3SumVec { .. } => Self::PRIO3_SUM_VEC,
            Self::Prio3Histogram { .. } => Self::PRIO3_HISTOGRAM,
            Self::Prio3MultihotCountVec { .. } => Self::PRIO3_MULTIHOT_COUNT_VEC,
            Self::Poplar1 { .. } => Self::POPLAR1,

            #[cfg(feature = "test-util")]
            Self::Fake { .. } => Self::FAKE,
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 { .. } => {
                Self::PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128
            }
        }
    }

    fn vdaf_config_len(&self) -> u16 {
        match self {
            Self::Reserved => 0,
            Self::Prio3Count => 0,
            Self::Prio3Sum { .. } => 4,
            Self::Prio3SumVec { .. } => 9,
            Self::Prio3Histogram { .. } => 8,
            Self::Prio3MultihotCountVec { .. } => 12,
            Self::Poplar1 { .. } => 2,

            #[cfg(feature = "test-util")]
            Self::Fake { .. } => 4,
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 { .. } => 10,
        }
    }
}

impl Encode for VdafConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.vdaf_type_code().encode(bytes)?;
        self.vdaf_config_len().encode(bytes)?;
        match self {
            Self::Reserved => (),
            Self::Prio3Count => (),
            Self::Prio3Sum { max_measurement } => {
                max_measurement.encode(bytes)?;
            }
            Self::Prio3SumVec {
                length,
                bits,
                chunk_length,
            } => {
                length.encode(bytes)?;
                bits.encode(bytes)?;
                chunk_length.encode(bytes)?;
            }
            Self::Prio3Histogram {
                length,
                chunk_length,
            } => {
                length.encode(bytes)?;
                chunk_length.encode(bytes)?;
            }
            Self::Prio3MultihotCountVec {
                length,
                chunk_length,
                max_weight,
            } => {
                length.encode(bytes)?;
                chunk_length.encode(bytes)?;
                max_weight.encode(bytes)?;
            }
            Self::Poplar1 { bits } => {
                bits.encode(bytes)?;
            }

            #[cfg(feature = "test-util")]
            Self::Fake { rounds } => {
                rounds.encode(bytes)?;
            }
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                length,
                bits,
                chunk_length,
                proofs,
            } => {
                length.encode(bytes)?;
                bits.encode(bytes)?;
                chunk_length.encode(bytes)?;
                proofs.encode(bytes)?;
            }
        }
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(4 + 2 + usize::from(self.vdaf_config_len()))
    }
}

impl Decode for VdafConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let vdaf_type_code = u32::decode(bytes)?;
        let vdaf_config_len = u16::decode(bytes)?;
        let vdaf_type = match vdaf_type_code {
            Self::RESERVED => Self::Reserved,
            Self::PRIO3_COUNT => Self::Prio3Count,
            Self::PRIO3_SUM => Self::Prio3Sum {
                max_measurement: u32::decode(bytes)?,
            },
            Self::PRIO3_SUM_VEC => Self::Prio3SumVec {
                length: u32::decode(bytes)?,
                bits: u8::decode(bytes)?,
                chunk_length: u32::decode(bytes)?,
            },
            Self::PRIO3_HISTOGRAM => Self::Prio3Histogram {
                length: u32::decode(bytes)?,
                chunk_length: u32::decode(bytes)?,
            },
            Self::PRIO3_MULTIHOT_COUNT_VEC => Self::Prio3MultihotCountVec {
                length: u32::decode(bytes)?,
                chunk_length: u32::decode(bytes)?,
                max_weight: u32::decode(bytes)?,
            },
            Self::POPLAR1 => Self::Poplar1 {
                bits: u16::decode(bytes)?,
            },

            #[cfg(feature = "test-util")]
            Self::FAKE => Self::Fake {
                rounds: u32::decode(bytes)?,
            },
            Self::PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128 => {
                Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    length: u32::decode(bytes)?,
                    bits: u8::decode(bytes)?,
                    chunk_length: u32::decode(bytes)?,
                    proofs: u8::decode(bytes)?,
                }
            }

            val => {
                return Err(CodecError::Other(
                    anyhow!("unexpected VDAF type code value {val}").into(),
                ));
            }
        };

        if vdaf_config_len != vdaf_type.vdaf_config_len() {
            return Err(CodecError::Other(
                anyhow!(
                    "VDAF config length prefix ({}) does not match expected value ({})",
                    vdaf_config_len,
                    vdaf_type.vdaf_config_len()
                )
                .into(),
            ));
        }

        Ok(vdaf_type)
    }
}

/// Taskprov message indicating an extension to a taskprov configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskbindExtension {
    extension_type: TaskbindExtensionType,
    extension_data: Vec<u8>,
}

impl TaskbindExtension {
    /// Construct an extension from its type and payload.
    pub fn new(extension_type: TaskbindExtensionType, extension_data: Vec<u8>) -> Self {
        Self {
            extension_type,
            extension_data,
        }
    }

    /// Returns the type of this extension.
    pub fn extension_type(&self) -> &TaskbindExtensionType {
        &self.extension_type
    }

    /// Returns the unparsed data representing this extension.
    pub fn extension_data(&self) -> &[u8] {
        &self.extension_data
    }
}

impl Encode for TaskbindExtension {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.extension_type.encode(bytes)?;
        encode_u16_items(bytes, &(), &self.extension_data)
    }

    fn encoded_len(&self) -> Option<usize> {
        // Type, length prefix, and extension data.
        Some(self.extension_type.encoded_len()? + 2 + self.extension_data.len())
    }
}

impl Decode for TaskbindExtension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extension_type = TaskbindExtensionType::decode(bytes)?;
        let extension_data = decode_u16_items(&(), bytes)?;

        Ok(Self {
            extension_type,
            extension_data,
        })
    }
}

/// Taskprov message indicating the type of a taskbind extension.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, TryFromPrimitive)]
#[repr(u16)]
#[non_exhaustive]
pub enum TaskbindExtensionType {
    Reserved = 0x0000,
}

impl Encode for TaskbindExtensionType {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u16).encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2)
    }
}

impl Decode for TaskbindExtensionType {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Self::try_from(val).map_err(|_| {
            CodecError::Other(anyhow!("unexpected TaskbindExtensionType value ({val})").into())
        })
    }
}

/// TaskProv protocol message representing a duration with a resolution of seconds.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TimePrecision(u64);

impl TimePrecision {
    pub const ZERO: TimePrecision = TimePrecision::from_seconds(0);

    /// Create a duration representing the provided number of seconds.
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Create a duration representing the provided number of hours.
    ///
    /// This is a convenience method for tests. For production code with time
    /// arithmetic, use `chrono::TimeDelta` and `from_chrono`.
    #[cfg(any(test, feature = "test-util"))]
    pub const fn from_hours(hours: u64) -> Self {
        Self(hours * 3600)
    }

    /// Get the number of seconds this duration represents.
    pub fn as_seconds(&self) -> u64 {
        self.0
    }

    /// Convert this [`TimePrecision`] into a [`chrono::TimeDelta`].
    ///
    /// Returns an error if the duration cannot be represented as a TimeDelta (e.g., the number of
    /// seconds is too large for i64 or the resulting milliseconds would overflow).
    pub fn to_chrono(&self) -> Result<chrono::TimeDelta, Error> {
        chrono::TimeDelta::try_seconds(
            self.0
                .try_into()
                .map_err(|_| Error::IllegalTimeArithmetic("number of seconds too big for i64"))?,
        )
        .ok_or(Error::IllegalTimeArithmetic(
            "number of milliseconds too big for i64",
        ))
    }
}

impl Encode for TimePrecision {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        self.0.encoded_len()
    }
}

impl Decode for TimePrecision {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        Ok(Self(u64::decode(bytes)?))
    }
}

impl Display for TimePrecision {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} seconds", self.0)
    }
}

/// This method is only as a bridge for Issue #4019, and will be removed.
impl From<TimePrecision> for Duration {
    fn from(value: TimePrecision) -> Self {
        Duration::from_seconds(value.as_seconds())
    }
}

/// This method is only as a bridge for Issue #4019, and will be removed.
impl From<Duration> for TimePrecision {
    fn from(duration: Duration) -> Self {
        TimePrecision::from_seconds(duration.as_seconds())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Time, TimePrecision, Url, batch_mode, roundtrip_encoding,
        taskprov::{TaskConfig, TaskbindExtension, TaskbindExtensionType, VdafConfig},
    };
    use assert_matches::assert_matches;
    use prio::codec::{CodecError, Decode as _};

    #[test]
    fn roundtrip_task_config() {
        roundtrip_encoding(&[
            (
                TaskConfig::new(
                    "foobar".as_bytes().to_vec(),
                    Url::try_from("https://example.com/".as_ref()).unwrap(),
                    Url::try_from("https://another.example.com/".as_ref()).unwrap(),
                    TimePrecision::from_seconds(3600),
                    10000,
                    batch_mode::Code::TimeInterval,
                    Time::from_seconds_since_epoch(1000000),
                    TimePrecision::from_seconds(100000),
                    VdafConfig::Prio3Count,
                    Vec::new(),
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
                    "0000000000000E10", // time_precision
                    "00002710",         // min_batch_size
                    "01",               // batch_mode
                    concat!(
                        // batch_config
                        "0000", // length
                    ),
                    "00000000000F4240", // task_start
                    "00000000000186A0", // task_duration
                    "00000001",         // vdaf_type
                    concat!(
                        // vdaf_config
                        "0000", // length
                    ),
                    concat!(
                        // extensions
                        "0000", // length
                    ),
                ),
            ),
            (
                TaskConfig::new(
                    "f".as_bytes().to_vec(),
                    Url::try_from("https://example.com/".as_ref()).unwrap(),
                    Url::try_from("https://another.example.com/".as_ref()).unwrap(),
                    TimePrecision::from_seconds(1000),
                    1000,
                    batch_mode::Code::LeaderSelected,
                    Time::from_seconds_since_epoch(10000000),
                    TimePrecision::from_seconds(50000),
                    VdafConfig::Prio3Sum {
                        max_measurement: 0xFF,
                    },
                    Vec::from([TaskbindExtension::new(
                        TaskbindExtensionType::Reserved,
                        Vec::from("0123"),
                    )]),
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
                    "00000000000003E8", // time_precision
                    "000003E8",         // min_batch_size
                    "02",               // batch_mode
                    concat!(
                        // batch_config
                        "0000", // length
                    ),
                    "0000000000989680", // task_start
                    "000000000000C350", // task_duration
                    "00000002",         // vdaf_type
                    concat!(
                        // vdaf_config
                        "0004",     // vdaf_config length
                        "000000FF", // max_measurement
                    ),
                    concat!(
                        // extensions
                        "0008", // length
                        concat!(
                            "0000",     // extension_type
                            "0004",     // extension_data length
                            "30313233", // extension_data
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
                        ""    // opaque data
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
                    "0000000000000E10", // time_precision
                    "00002710",         // min_batch_size
                    "01",               // batch_mode
                    concat!(
                        // batch_config
                        "0000", // length
                    ),
                    "00000000000F4240", // task_start
                    "00000000000186A0", // task_duration
                    "00000001",         // vdaf_type
                    concat!(
                        // vdaf_config
                        "0000", // length
                    ),
                    concat!(
                        // extensions
                        "0000", // length
                    ),
                ))
                .unwrap(),
            ),
            Err(CodecError::Other(_))
        );
    }

    #[test]
    fn roundtrip_vdaf_config() {
        roundtrip_encoding(&[
            (
                VdafConfig::Reserved,
                concat!(
                    "00000000", // vdaf_type
                    "0000",     // vdaf_config length
                    "",         // vdaf_config
                ),
            ),
            (
                VdafConfig::Prio3Count,
                concat!(
                    "00000001", // vdaf_type
                    "0000",     // vdaf_config length
                    "",         // vdaf_config
                ),
            ),
            (
                VdafConfig::Prio3Sum {
                    max_measurement: u32::MIN,
                },
                concat!(
                    "00000002", // vdaf_type
                    "0004",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "00000000", // max_measurement
                    ),
                ),
            ),
            (
                VdafConfig::Prio3Sum {
                    max_measurement: 0xFF,
                },
                concat!(
                    "00000002", // vdaf_type
                    "0004",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "000000FF", // max_measurement
                    ),
                ),
            ),
            (
                VdafConfig::Prio3Sum {
                    max_measurement: u32::MAX,
                },
                concat!(
                    "00000002", // vdaf_type
                    "0004",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "FFFFFFFF", // max_measurement
                    ),
                ),
            ),
            (
                VdafConfig::Prio3SumVec {
                    length: 12,
                    bits: 8,
                    chunk_length: 14,
                },
                concat!(
                    "00000003", // vdaf_type
                    "0009",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "0000000C", // length
                        "08",       // bits
                        "0000000E"  // chunk_length
                    ),
                ),
            ),
            (
                VdafConfig::Prio3Histogram {
                    length: 256,
                    chunk_length: 18,
                },
                concat!(
                    "00000004", // vdaf_type
                    "0008",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "00000100", // length
                        "00000012", // chunk_length
                    ),
                ),
            ),
            (
                VdafConfig::Prio3MultihotCountVec {
                    length: 256,
                    chunk_length: 18,
                    max_weight: 14,
                },
                concat!(
                    "00000005", // vdaf_type
                    "000C",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "00000100", // length
                        "00000012", // chunk_length
                        "0000000E", // max_weight
                    ),
                ),
            ),
            (
                VdafConfig::Poplar1 { bits: 32 },
                concat!(
                    "00000006", // vdaf_type
                    "0002",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "0020", // bits
                    ),
                ),
            ),
            (
                VdafConfig::Fake { rounds: 15 },
                concat!(
                    "FFFF0000", // vdaf_type
                    "0004",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "0000000F", // rounds
                    ),
                ),
            ),
            (
                VdafConfig::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    length: 12,
                    bits: 8,
                    chunk_length: 14,
                    proofs: 2,
                },
                concat!(
                    "FFFF1003", // vdaf_type
                    "000A",     // vdaf_config length
                    concat!(
                        // vdaf_config
                        "0000000C", // length
                        "08",       // bits
                        "0000000E", // chunk_length
                        "02"        // proofs
                    ),
                ),
            ),
        ])
    }

    #[test]
    fn roundtrip_taskbind_extension() {
        roundtrip_encoding(&[
            (
                TaskbindExtension::new(TaskbindExtensionType::Reserved, Vec::new()),
                concat!(
                    "0000", // extension_type
                    "0000", // extension_data length
                    "",     // extension_data
                ),
            ),
            (
                TaskbindExtension::new(TaskbindExtensionType::Reserved, Vec::from("0123")),
                concat!(
                    "0000",     // extension_type
                    "0004",     // extension_data length
                    "30313233", // extension_data
                ),
            ),
        ]);
    }

    #[test]
    fn roundtrip_taskbind_extension_type() {
        roundtrip_encoding(&[(TaskbindExtensionType::Reserved, "0000")]);
    }
}
