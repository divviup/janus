use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    CollectionJobId, Duration, Time,
};

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

#[derive(Debug, Clone)]
pub(super) enum Query {
    TimeInterval(janus_messages::Query<TimeInterval>),
    FixedSize(janus_messages::Query<FixedSize>),
}
