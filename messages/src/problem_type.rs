use std::str::FromStr;

/// Representation of the different problem types defined in [DAP][1].
///
/// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-15.html#table-1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DapProblemType {
    InvalidMessage,
    UnrecognizedTask,
    UnrecognizedAggregationJob,
    BatchInvalid,
    InvalidBatchSize,
    InvalidAggregationParameter,
    BatchMismatch,
    StepMismatch,
    BatchOverlap,
    UnsupportedExtension,
    /// A task defined via Taskprov was rejected by the aggregator. Error defined by
    /// draft-ietf-ppm-dap-taskprov ([1]).
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-taskprov-01#table-1
    InvalidTask,
}

impl DapProblemType {
    /// Returns the problem type URI for a particular kind of error.
    pub fn type_uri(&self) -> &'static str {
        match self {
            DapProblemType::InvalidMessage => "urn:ietf:params:ppm:dap:error:invalidMessage",
            DapProblemType::UnrecognizedTask => "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            DapProblemType::UnrecognizedAggregationJob => {
                "urn:ietf:params:ppm:dap:error:unrecognizedAggregationJob"
            }
            DapProblemType::BatchInvalid => "urn:ietf:params:ppm:dap:error:batchInvalid",
            DapProblemType::InvalidBatchSize => "urn:ietf:params:ppm:dap:error:invalidBatchSize",
            DapProblemType::InvalidAggregationParameter => {
                "urn:ietf:params:ppm:dap:error:invalidAggregationParameter"
            }
            DapProblemType::BatchMismatch => "urn:ietf:params:ppm:dap:error:batchMismatch",
            DapProblemType::StepMismatch => "urn:ietf:params:ppm:dap:error:stepMismatch",
            DapProblemType::BatchOverlap => "urn:ietf:params:ppm:dap:error:batchOverlap",
            DapProblemType::UnsupportedExtension => {
                "urn:ietf:params:ppm:dap:error:unsupportedExtension"
            }
            DapProblemType::InvalidTask => "urn:ietf:params:ppm:dap:error:invalidTask",
        }
    }

    /// Returns a human-readable summary of a problem type.
    pub fn description(&self) -> &'static str {
        match self {
            DapProblemType::InvalidMessage => {
                "The message type for a response was incorrect or the payload was malformed."
            }
            DapProblemType::UnrecognizedTask => {
                "An endpoint received a message with an unknown task ID."
            }
            DapProblemType::UnrecognizedAggregationJob => {
                "An endpoint received a message with an unknown aggregation job ID."
            }
            DapProblemType::BatchInvalid => "The batch implied by the query is invalid.",
            DapProblemType::InvalidBatchSize => {
                "The number of reports included in the batch is invalid."
            }
            DapProblemType::InvalidAggregationParameter => "The aggregation parameter is invalid.",
            DapProblemType::BatchMismatch => {
                "Leader and helper disagree on reports aggregated in a batch."
            }
            DapProblemType::StepMismatch => {
                "The leader and helper are not on the same step of VDAF preparation."
            }
            DapProblemType::BatchOverlap => {
                "The queried batch overlaps with a previously queried batch."
            }
            DapProblemType::UnsupportedExtension => "The report includes an unsupported extension.",
            DapProblemType::InvalidTask => "Aggregator has opted out of the indicated task.",
        }
    }
}

/// An error indicating a problem type URI was not recognized as a DAP problem type.
#[derive(Debug)]
pub struct DapProblemTypeParseError;

impl FromStr for DapProblemType {
    type Err = DapProblemTypeParseError;

    fn from_str(value: &str) -> Result<DapProblemType, DapProblemTypeParseError> {
        match value {
            "urn:ietf:params:ppm:dap:error:invalidMessage" => Ok(DapProblemType::InvalidMessage),
            "urn:ietf:params:ppm:dap:error:unrecognizedTask" => {
                Ok(DapProblemType::UnrecognizedTask)
            }
            "urn:ietf:params:ppm:dap:error:unrecognizedAggregationJob" => {
                Ok(DapProblemType::UnrecognizedAggregationJob)
            }
            "urn:ietf:params:ppm:dap:error:batchInvalid" => Ok(DapProblemType::BatchInvalid),
            "urn:ietf:params:ppm:dap:error:invalidBatchSize" => {
                Ok(DapProblemType::InvalidBatchSize)
            }
            "urn:ietf:params:ppm:dap:error:batchMismatch" => Ok(DapProblemType::BatchMismatch),
            "urn:ietf:params:ppm:dap:error:stepMismatch" => Ok(DapProblemType::StepMismatch),
            "urn:ietf:params:ppm:dap:error:batchOverlap" => Ok(DapProblemType::BatchOverlap),
            "urn:ietf:params:ppm:dap:error:unsupportedExtension" => {
                Ok(DapProblemType::UnsupportedExtension)
            }
            "urn:ietf:params:ppm:dap:error:invalidTask" => Ok(DapProblemType::InvalidTask),
            _ => Err(DapProblemTypeParseError),
        }
    }
}
