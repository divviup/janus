use janus_aggregator_core::task::AggregationMode;
use janus_messages::{CollectionJobId, Duration, Interval, Time};

#[derive(Debug, Clone)]
pub(super) struct Input {
    /// Task batch mode selector. This is fixed by the test harness, and not randomly generated.
    pub(super) is_leader_selected: bool,

    /// Combination of Janus configuration and task parameters.
    pub(super) config: Config,

    /// Simulation operations to run.
    pub(super) ops: Vec<Op>,
}

#[derive(Debug, Clone)]
pub(super) struct Config {
    /// DAP task parameter: time precision.
    pub(super) time_precision: Duration,

    /// DAP task parameter: minimum batch size.
    pub(super) min_batch_size: u64,

    /// Janus-specific task parameter: batch time window size (for the time-bucketed leader-selected
    /// feature). This is only used with leader-selected tasks, and ignored otherwise.
    pub(super) batch_time_window_size: Option<Duration>,

    /// Janus-specific task parameter: report expiry age (for garbage collection).
    pub(super) report_expiry_age: Option<Duration>,

    /// Janus-specific task parameter: aggregation mode. This is only used by the helper, and
    /// ignored otherwise.
    pub(super) aggregation_mode: AggregationMode,

    /// Aggregation job creator configuration: minimum aggregation job size.
    pub(super) min_aggregation_job_size: usize,

    /// Aggregation job creator configuration: maximum aggregation job size.
    pub(super) max_aggregation_job_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Op {
    /// Advance the `MockClock`'s time by `amount`.
    AdvanceTime { amount: Duration },

    /// Upload some reports.
    ///
    /// Have the client shard some reports at the given timestamp, with the next sequential
    /// measurements, and send them to the leader aggregator. The leader will handle the requests
    /// and store the reports to the database. Note that, as currently implemented, this will wait
    /// for the report batching timeout to expire, so the client's upload method won't return until
    /// the leader's database transaction is complete.
    Upload { report_time: Time, count: u8 },

    ///  Have the client shard and upload a report at the given timestamp, but with a fixed report
    ///  ID.
    UploadReplay { report_time: Time },

    /// Have the client shard and upload a report at the given timestamp, but without rounding its
    /// timestamp to the time precision.
    UploadNotRounded { report_time: Time },

    /// Have the client upload an invalid (but correctly formatted) report at the given timestamp.
    UploadInvalid { report_time: Time },

    /// Run the garbage collector once in the leader.
    LeaderGarbageCollector,

    /// Run the garbage collector once in the helper.
    HelperGarbageCollector,

    /// Run the key rotator once in the leader.
    LeaderKeyRotator,

    /// Run the key rotator once in the helper.
    HelperKeyRotator,

    /// Run the aggregation job creator once.
    AggregationJobCreator,

    /// Run the aggregation job driver once in the leader, and wait until it is done stepping all
    /// the jobs it acquired.
    ///
    /// Requests and responses will pass through an inspecting proxy in front of the helper.
    LeaderAggregationJobDriver,

    /// Same as `LeaderAggregationJobDriver`, with fault injection. Drop all requests and return some sort
    /// of error.
    LeaderAggregationJobDriverRequestError,

    /// Same as `LeaderAggregationJobDriver`, with fault injection. Forward all requests, but drop the
    /// responses, and return some sort of error.
    LeaderAggregationJobDriverResponseError,

    /// Run the aggregation job driver once in the helper, and wait until it is done stepping all
    /// the jobs it acquired.
    ///
    /// Note that the helper aggregation job driver makes no outgoing requests. It only updates its
    /// own database.
    HelperAggregationJobDriver,

    /// Run the collection job driver once, and wait until it is done stepping all the jobs it
    /// acquired.
    ///
    /// Requests and responses will pass through an inspecting proxy in front of the helper.
    CollectionJobDriver,

    /// Same as `CollectionJobDriver`, with fault injection.
    ///
    /// Drop all requests and return some sort of error.
    CollectionJobDriverRequestError,

    /// Same as `CollectionJobDriver`, with fault injection.
    ///
    /// Forward all requests, but drop the responses, and return some sort of error.
    CollectionJobDriverResponseError,

    /// The collector sends a collection request to the leader. It remembers the collection job ID.
    CollectorStart {
        collection_job_id: CollectionJobId,
        query: Query,
    },

    /// The collector sends a request to the leader to poll an existing collection job.
    CollectorPoll { collection_job_id: CollectionJobId },
}

/// Representation of a DAP query used in a collection job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Query {
    /// A time interval query, parameterized with a batch interval.
    TimeInterval(Interval),
    /// A leader-selected query.
    LeaderSelected,
}
