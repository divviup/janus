use std::str::FromStr;

/// Representation of the different problem types defined in Table 1 in §3.2.
#[derive(Debug, PartialEq, Eq)]
pub enum DapProblemType {
    InvalidMessage,
    UnrecognizedTask,
    StepMismatch,
    MissingTaskId,
    UnrecognizedAggregationJob,
    OutdatedConfig,
    ReportRejected,
    ReportTooEarly,
    BatchInvalid,
    InvalidBatchSize,
    BatchQueriedTooManyTimes,
    BatchMismatch,
    UnauthorizedRequest,
    BatchOverlap,
    InvalidTask,
}

impl DapProblemType {
    /// Returns the problem type URI for a particular kind of error.
    pub fn type_uri(&self) -> &'static str {
        match self {
            DapProblemType::InvalidMessage => "urn:ietf:params:ppm:dap:error:invalidMessage",
            DapProblemType::UnrecognizedTask => "urn:ietf:params:ppm:dap:error:unrecognizedTask",
            DapProblemType::StepMismatch => "urn:ietf:params:ppm:dap:error:stepMismatch",
            DapProblemType::MissingTaskId => "urn:ietf:params:ppm:dap:error:missingTaskID",
            DapProblemType::UnrecognizedAggregationJob => {
                "urn:ietf:params:ppm:dap:error:unrecognizedAggregationJob"
            }
            DapProblemType::OutdatedConfig => "urn:ietf:params:ppm:dap:error:outdatedConfig",
            DapProblemType::ReportRejected => "urn:ietf:params:ppm:dap:error:reportRejected",
            DapProblemType::ReportTooEarly => "urn:ietf:params:ppm:dap:error:reportTooEarly",
            DapProblemType::BatchInvalid => "urn:ietf:params:ppm:dap:error:batchInvalid",
            DapProblemType::InvalidBatchSize => "urn:ietf:params:ppm:dap:error:invalidBatchSize",
            DapProblemType::BatchQueriedTooManyTimes => {
                "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes"
            }
            DapProblemType::BatchMismatch => "urn:ietf:params:ppm:dap:error:batchMismatch",
            DapProblemType::UnauthorizedRequest => {
                "urn:ietf:params:ppm:dap:error:unauthorizedRequest"
            }
            DapProblemType::BatchOverlap => "urn:ietf:params:ppm:dap:error:batchOverlap",
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
            DapProblemType::StepMismatch => {
                "The leader and helper are not on the same step of VDAF preparation."
            }
            DapProblemType::MissingTaskId => {
                "HPKE configuration was requested without specifying a task ID."
            }
            DapProblemType::UnrecognizedAggregationJob => {
                "An endpoint received a message with an unknown aggregation job ID."
            }
            DapProblemType::OutdatedConfig => {
                "The message was generated using an outdated configuration."
            }
            DapProblemType::ReportRejected => "Report could not be processed.",
            DapProblemType::ReportTooEarly => {
                "Report could not be processed because it arrived too early."
            }
            DapProblemType::BatchInvalid => "The batch implied by the query is invalid.",
            DapProblemType::InvalidBatchSize => {
                "The number of reports included in the batch is invalid."
            }
            DapProblemType::BatchQueriedTooManyTimes => {
                "The batch described by the query has been queried too many times."
            }
            DapProblemType::BatchMismatch => {
                "Leader and helper disagree on reports aggregated in a batch."
            }
            DapProblemType::UnauthorizedRequest => "The request's authorization is not valid.",
            DapProblemType::BatchOverlap => {
                "The queried batch overlaps with a previously queried batch."
            }
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
            "urn:ietf:params:ppm:dap:error:stepMismatch" => Ok(DapProblemType::StepMismatch),
            "urn:ietf:params:ppm:dap:error:missingTaskID" => Ok(DapProblemType::MissingTaskId),
            "urn:ietf:params:ppm:dap:error:unrecognizedAggregationJob" => {
                Ok(DapProblemType::UnrecognizedAggregationJob)
            }
            "urn:ietf:params:ppm:dap:error:outdatedConfig" => Ok(DapProblemType::OutdatedConfig),
            "urn:ietf:params:ppm:dap:error:reportRejected" => Ok(DapProblemType::ReportRejected),
            "urn:ietf:params:ppm:dap:error:reportTooEarly" => Ok(DapProblemType::ReportTooEarly),
            "urn:ietf:params:ppm:dap:error:batchInvalid" => Ok(DapProblemType::BatchInvalid),
            "urn:ietf:params:ppm:dap:error:invalidBatchSize" => {
                Ok(DapProblemType::InvalidBatchSize)
            }
            "urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes" => {
                Ok(DapProblemType::BatchQueriedTooManyTimes)
            }
            "urn:ietf:params:ppm:dap:error:batchMismatch" => Ok(DapProblemType::BatchMismatch),
            "urn:ietf:params:ppm:dap:error:unauthorizedRequest" => {
                Ok(DapProblemType::UnauthorizedRequest)
            }
            "urn:ietf:params:ppm:dap:error:batchOverlap" => Ok(DapProblemType::BatchOverlap),
            "urn:ietf:params:ppm:dap:error:invalidTask" => Ok(DapProblemType::InvalidTask),
            _ => Err(DapProblemTypeParseError),
        }
    }
}
