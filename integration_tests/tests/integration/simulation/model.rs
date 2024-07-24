use janus_messages::{CollectionJobId, Duration, Interval, Time};

#[derive(Debug, Clone)]
pub(super) struct Input {
    pub(super) is_fixed_size: bool,
    pub(super) config: Config,
    pub(super) ops: Vec<Op>,
}

#[derive(Debug, Clone)]
pub(super) struct Config {
    pub(super) time_precision: Duration,
    pub(super) min_batch_size: u64,
    pub(super) max_batch_size: Option<u64>,
    pub(super) report_expiry_age: Option<Duration>,
    pub(super) min_aggregation_job_size: usize,
    pub(super) max_aggregation_job_size: usize,
}

#[derive(Debug, Clone)]
pub(super) enum Op {
    AdvanceTime {
        amount: Duration,
    },
    Upload {
        report_time: Time,
    },
    UploadReplay {
        report_time: Time,
    },
    LeaderGarbageCollector,
    HelperGarbageCollector,
    LeaderKeyRotator,
    HelperKeyRotator,
    AggregationJobCreator,
    AggregationJobDriver,
    AggregationJobDriverRequestError,
    AggregationJobDriverResponseError,
    CollectionJobDriver,
    CollectionJobDriverRequestError,
    CollectionJobDriverResponseError,
    CollectorStart {
        collection_job_id: CollectionJobId,
        query: Query,
    },
    CollectorPoll {
        collection_job_id: CollectionJobId,
    },
}

/// Representation of a DAP query used in a collection job.
#[derive(Debug, Clone)]
pub(super) enum Query {
    /// A time interval query, parameterized with a batch interval.
    TimeInterval(Interval),
    /// A current batch query.
    FixedSizeCurrentBatch,
    /// A "by batch ID" query. The batch ID will be taken from a previous collection result, with
    /// the given collection job ID.
    FixedSizeByBatchId(CollectionJobId),
}
