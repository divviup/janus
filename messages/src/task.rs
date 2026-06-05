//! Task configuration data structures as defined in DAP-18[1].
//!
//! [1]: https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/18/

use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    io::{Cursor, Read},
};

use anyhow::anyhow;
use prio::codec::{
    CodecError, Decode, Encode, decode_u8_items, decode_u16_items, encode_u8_items,
    encode_u16_items,
};

use crate::{Duration, Error, Interval, Time, TimePrecision, Url, batch_mode};

/// Defines all parameters necessary to configure a DAP task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskConfiguration {
    task_info: Vec<u8>,
    leader_aggregator_endpoint: Url,
    helper_aggregator_endpoint: Url,
    time_precision: TimePrecision,
    min_batch_size: u64,
    batch_mode: batch_mode::Code,
    batch_config: Vec<u8>,
    vdaf_config: VdafConfig,
    extensions: Vec<TaskExtension>,
}

impl TaskConfiguration {
    /// Validates that extension types are in strictly increasing order (per DAP-18 §4.2.2).
    fn validate_extensions(extensions: &[TaskExtension]) -> Result<(), Error> {
        if extensions.is_sorted_by(|a, b| a.extension_type() < b.extension_type()) {
            Ok(())
        } else {
            Err(Error::InvalidParameter(
                "task extensions must be in strictly increasing order of extension_type",
            ))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_info: Vec<u8>,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: TimePrecision,
        min_batch_size: u64,
        batch_mode: batch_mode::Code,
        batch_config: Vec<u8>,
        vdaf_config: VdafConfig,
        extensions: Vec<TaskExtension>,
    ) -> Result<Self, Error> {
        if task_info.is_empty() {
            return Err(Error::InvalidParameter("task_info must not be empty"));
        }
        if task_info.len() > u8::MAX as usize {
            return Err(Error::InvalidParameter(
                "task_info must not exceed 255 bytes",
            ));
        }
        Self::validate_extensions(&extensions)?;

        Ok(Self {
            task_info,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            min_batch_size,
            batch_mode,
            batch_config,
            vdaf_config,
            extensions,
        })
    }

    /// Convenience constructor that creates a `task_interval` extension from the provided
    /// `task_start` and `task_duration`, inserting it at the correct sorted position in the
    /// given extensions.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_task_interval(
        task_info: Vec<u8>,
        leader_aggregator_endpoint: Url,
        helper_aggregator_endpoint: Url,
        time_precision: TimePrecision,
        min_batch_size: u64,
        batch_mode: batch_mode::Code,
        batch_config: Vec<u8>,
        task_start: Time,
        task_duration: Duration,
        vdaf_config: VdafConfig,
        mut extensions: Vec<TaskExtension>,
    ) -> Result<Self, Error> {
        if extensions
            .iter()
            .any(|e| *e.extension_type() == TaskExtensionType::TaskInterval)
        {
            return Err(Error::InvalidParameter(
                "extensions already contains a task_interval extension",
            ));
        }
        let insert_pos = extensions
            .iter()
            .position(|e| *e.extension_type() > TaskExtensionType::TaskInterval)
            .unwrap_or(extensions.len());
        extensions.insert(
            insert_pos,
            TaskExtension::new_task_interval(task_start, task_duration)?,
        );
        Self::new(
            task_info,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            min_batch_size,
            batch_mode,
            batch_config,
            vdaf_config,
            extensions,
        )
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

    pub fn min_batch_size(&self) -> u64 {
        self.min_batch_size
    }

    pub fn batch_mode(&self) -> &batch_mode::Code {
        &self.batch_mode
    }

    pub fn batch_config(&self) -> &[u8] {
        &self.batch_config
    }

    pub fn vdaf_config(&self) -> &VdafConfig {
        &self.vdaf_config
    }

    pub fn extensions(&self) -> &[TaskExtension] {
        &self.extensions
    }

    /// Searches extensions for a `task_interval` extension and decodes it.
    pub fn task_interval(&self) -> Result<Option<Interval>, Error> {
        // Duplicates are prevented by validate_extensions (strictly increasing order).
        self.extensions
            .iter()
            .find(|e| *e.extension_type() == TaskExtensionType::TaskInterval)
            .map(|ext| ext.as_task_interval())
            .transpose()
    }
}

impl Encode for TaskConfiguration {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_u8_items(bytes, &(), &self.task_info)?;
        self.leader_aggregator_endpoint.encode(bytes)?;
        self.helper_aggregator_endpoint.encode(bytes)?;
        self.time_precision.encode(bytes)?;
        self.min_batch_size.encode(bytes)?;
        self.batch_mode.encode(bytes)?;
        encode_u16_items(bytes, &(), &self.batch_config)?;
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
            + self.batch_mode.encoded_len()?
            + (2 + self.batch_config.len())
            + self.vdaf_config.encoded_len()?;

        // Extensions.
        len += 2;
        for extension in &self.extensions {
            len += extension.encoded_len()?;
        }

        Some(len)
    }
}

impl Decode for TaskConfiguration {
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
        let min_batch_size = u64::decode(bytes)?;
        let batch_mode = batch_mode::Code::decode(bytes)?;
        let batch_config = decode_u16_items(&(), bytes)?;
        let vdaf_config = VdafConfig::decode(bytes)?;
        let extensions: Vec<TaskExtension> = decode_u16_items(&(), bytes)?;

        Self::validate_extensions(&extensions).map_err(|e| CodecError::Other(Box::new(e)))?;

        Ok(Self {
            task_info,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            time_precision,
            min_batch_size,
            batch_mode,
            batch_config,
            vdaf_config,
            extensions,
        })
    }
}

/// DAP message indicating a VDAF configuration. Encodes as a VdafType code (u32) followed by a
/// length-prefixed opaque vdaf_configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VdafConfig {
    Reserved,
    Prio3Count,
    Prio3Sum {
        /// Largest summand.
        max_measurement: u64,
    },
    Prio3SumVec {
        /// Length of the vector.
        length: u32,
        /// Largest summand.
        max_measurement: u64,
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
        max_weight: u64,
    },

    #[cfg(feature = "test-util")]
    #[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
    Fake {
        rounds: u32,
    },
    Prio3SumVecField64MultiproofHmacSha256Aes128 {
        /// Number of summands.
        length: u32,
        /// Largest summand.
        max_measurement: u64,
        /// Size of each proof chunk.
        chunk_length: u32,
        /// Number of proofs.
        proofs: u8,
    },
    Unknown {
        vdaf_type: u32,
        vdaf_configuration: Vec<u8>,
    },
}

impl VdafConfig {
    const RESERVED: u32 = 0x00000000;
    const PRIO3_COUNT: u32 = 0x00000001;
    const PRIO3_SUM: u32 = 0x00000002;
    const PRIO3_SUM_VEC: u32 = 0x00000003;
    const PRIO3_HISTOGRAM: u32 = 0x00000004;
    const PRIO3_MULTIHOT_COUNT_VEC: u32 = 0x00000005;

    #[cfg(feature = "test-util")]
    const FAKE: u32 = 0xFFFF0000;
    const PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128: u32 = 0xFFFF1003;

    pub fn vdaf_type(&self) -> u32 {
        match self {
            Self::Reserved => Self::RESERVED,
            Self::Prio3Count => Self::PRIO3_COUNT,
            Self::Prio3Sum { .. } => Self::PRIO3_SUM,
            Self::Prio3SumVec { .. } => Self::PRIO3_SUM_VEC,
            Self::Prio3Histogram { .. } => Self::PRIO3_HISTOGRAM,
            Self::Prio3MultihotCountVec { .. } => Self::PRIO3_MULTIHOT_COUNT_VEC,

            #[cfg(feature = "test-util")]
            Self::Fake { .. } => Self::FAKE,
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 { .. } => {
                Self::PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128
            }
            Self::Unknown { vdaf_type, .. } => *vdaf_type,
        }
    }

    fn vdaf_config_len(&self) -> Result<u16, CodecError> {
        Ok(match self {
            Self::Reserved => 0,
            Self::Prio3Count => 0,
            Self::Prio3Sum { .. } => 8,
            Self::Prio3SumVec { .. } => 16,
            Self::Prio3Histogram { .. } => 8,
            Self::Prio3MultihotCountVec { .. } => 16,

            #[cfg(feature = "test-util")]
            Self::Fake { .. } => 4,
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 { .. } => 17,
            Self::Unknown {
                vdaf_configuration, ..
            } => u16::try_from(vdaf_configuration.len()).map_err(|_| {
                CodecError::Other(anyhow!("vdaf_configuration exceeds u16::MAX bytes").into())
            })?,
        })
    }
}

impl Encode for VdafConfig {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.vdaf_type().encode(bytes)?;
        self.vdaf_config_len()?.encode(bytes)?;
        match self {
            Self::Reserved => (),
            Self::Prio3Count => (),
            Self::Prio3Sum { max_measurement } => {
                max_measurement.encode(bytes)?;
            }
            Self::Prio3SumVec {
                length,
                max_measurement,
                chunk_length,
            } => {
                length.encode(bytes)?;
                max_measurement.encode(bytes)?;
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

            #[cfg(feature = "test-util")]
            Self::Fake { rounds } => {
                rounds.encode(bytes)?;
            }
            Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                length,
                max_measurement,
                chunk_length,
                proofs,
            } => {
                length.encode(bytes)?;
                max_measurement.encode(bytes)?;
                chunk_length.encode(bytes)?;
                proofs.encode(bytes)?;
            }
            Self::Unknown {
                vdaf_configuration, ..
            } => {
                bytes.extend_from_slice(vdaf_configuration);
            }
        }
        Ok(())
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(4 + 2 + usize::from(self.vdaf_config_len().ok()?))
    }
}

impl Decode for VdafConfig {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let vdaf_type_code = u32::decode(bytes)?;
        let vdaf_config_len = usize::from(u16::decode(bytes)?);

        let mut config_buf = vec![0u8; vdaf_config_len];
        bytes.read_exact(&mut config_buf).map_err(|_| {
            CodecError::Other(
                anyhow!(
                    "vdaf_configuration length prefix ({vdaf_config_len}) exceeds available data"
                )
                .into(),
            )
        })?;

        let mut sub = Cursor::new(config_buf.as_slice());

        let vdaf_config = match vdaf_type_code {
            Self::RESERVED => Self::Reserved,
            Self::PRIO3_COUNT => Self::Prio3Count,
            Self::PRIO3_SUM => Self::Prio3Sum {
                max_measurement: u64::decode(&mut sub)?,
            },
            Self::PRIO3_SUM_VEC => Self::Prio3SumVec {
                length: u32::decode(&mut sub)?,
                max_measurement: u64::decode(&mut sub)?,
                chunk_length: u32::decode(&mut sub)?,
            },
            Self::PRIO3_HISTOGRAM => Self::Prio3Histogram {
                length: u32::decode(&mut sub)?,
                chunk_length: u32::decode(&mut sub)?,
            },
            Self::PRIO3_MULTIHOT_COUNT_VEC => Self::Prio3MultihotCountVec {
                length: u32::decode(&mut sub)?,
                chunk_length: u32::decode(&mut sub)?,
                max_weight: u64::decode(&mut sub)?,
            },

            #[cfg(feature = "test-util")]
            Self::FAKE => Self::Fake {
                rounds: u32::decode(&mut sub)?,
            },
            Self::PRIO3_SUM_VEC_FIELD64_MULTIPROOF_HMAC_SHA256_AES128 => {
                Self::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                    length: u32::decode(&mut sub)?,
                    max_measurement: u64::decode(&mut sub)?,
                    chunk_length: u32::decode(&mut sub)?,
                    proofs: u8::decode(&mut sub)?,
                }
            }

            _ => {
                return Ok(Self::Unknown {
                    vdaf_type: vdaf_type_code,
                    vdaf_configuration: config_buf,
                });
            }
        };

        if sub.position() as usize != vdaf_config_len {
            return Err(CodecError::Other(
                anyhow!(
                    "vdaf_configuration has {} trailing bytes",
                    vdaf_config_len - sub.position() as usize
                )
                .into(),
            ));
        }

        Ok(vdaf_config)
    }
}

/// DAP message indicating an extension to a task configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskExtension {
    extension_type: TaskExtensionType,
    extension_data: Vec<u8>,
}

impl TaskExtension {
    /// Construct an extension from its type and raw payload. For `TaskInterval` extensions,
    /// prefer [`Self::new_task_interval`] which encodes the interval correctly.
    pub fn new(extension_type: TaskExtensionType, extension_data: Vec<u8>) -> Self {
        Self {
            extension_type,
            extension_data,
        }
    }

    /// Create a `task_interval` extension from a start time and duration.
    pub fn new_task_interval(start: Time, duration: Duration) -> Result<Self, Error> {
        let interval = Interval::new(start, duration)?;
        // CodecError is intentionally discarded: it doesn't implement Into<Error>, and
        // Interval encoding can't practically fail.
        let extension_data = interval
            .get_encoded()
            .map_err(|_| Error::InvalidParameter("failed to encode task interval"))?;
        Ok(Self {
            extension_type: TaskExtensionType::TaskInterval,
            extension_data,
        })
    }

    pub fn extension_type(&self) -> &TaskExtensionType {
        &self.extension_type
    }

    pub fn extension_data(&self) -> &[u8] {
        &self.extension_data
    }

    /// Decode the extension data as a task interval, if this is a `TaskInterval` extension.
    pub fn as_task_interval(&self) -> Result<Interval, Error> {
        if self.extension_type != TaskExtensionType::TaskInterval {
            return Err(Error::InvalidParameter(
                "extension is not a task_interval extension",
            ));
        }
        Ok(Interval::get_decoded(&self.extension_data)?)
    }
}

impl Encode for TaskExtension {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        self.extension_type.encode(bytes)?;
        encode_u16_items(bytes, &(), &self.extension_data)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(self.extension_type.encoded_len()? + 2 + self.extension_data.len())
    }
}

impl Decode for TaskExtension {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extension_type = TaskExtensionType::decode(bytes)?;
        let extension_data = decode_u16_items(&(), bytes)?;

        Ok(Self {
            extension_type,
            extension_data,
        })
    }
}

/// DAP message indicating the type of a task extension.
///
/// Equality, ordering, and hashing are all defined in terms of the underlying codepoint, so
/// `Unknown(0x0001)` compares and hashes equal to `TaskInterval`.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum TaskExtensionType {
    Reserved,
    TaskInterval,
    Unknown(u16),
}

impl TaskExtensionType {
    const RESERVED: u16 = 0x0000;
    const TASK_INTERVAL: u16 = 0x0001;
}

impl From<u16> for TaskExtensionType {
    fn from(value: u16) -> Self {
        match value {
            Self::RESERVED => Self::Reserved,
            Self::TASK_INTERVAL => Self::TaskInterval,
            other => Self::Unknown(other),
        }
    }
}

impl From<TaskExtensionType> for u16 {
    fn from(value: TaskExtensionType) -> Self {
        match value {
            TaskExtensionType::Reserved => TaskExtensionType::RESERVED,
            TaskExtensionType::TaskInterval => TaskExtensionType::TASK_INTERVAL,
            TaskExtensionType::Unknown(val) => val,
        }
    }
}

impl PartialEq for TaskExtensionType {
    fn eq(&self, other: &Self) -> bool {
        u16::from(*self) == u16::from(*other)
    }
}

impl Eq for TaskExtensionType {}

impl Hash for TaskExtensionType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        u16::from(*self).hash(state)
    }
}

impl PartialOrd for TaskExtensionType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TaskExtensionType {
    fn cmp(&self, other: &Self) -> Ordering {
        u16::from(*self).cmp(&u16::from(*other))
    }
}

impl Encode for TaskExtensionType {
    fn encode(&self, bytes: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(*self).encode(bytes)
    }

    fn encoded_len(&self) -> Option<usize> {
        Some(2)
    }
}

impl Decode for TaskExtensionType {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let val = u16::decode(bytes)?;
        Ok(Self::from(val))
    }
}
