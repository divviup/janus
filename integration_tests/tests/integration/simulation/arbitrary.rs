//! `Arbitrary` implementations to generate simulation inputs.

// TODO: There will be perennial opportunities to make the distribution of inputs more "realistic"
// and/or "interesting", to control more configuration from simulation inputs, and to introduce new
// forms of fault injection. See https://users.cs.utah.edu/~regehr/papers/swarm12.pdf for example.

use std::cmp::max;

use janus_core::time::{DurationExt, TimeExt};
use janus_messages::{CollectionJobId, Duration, Interval, Time};
use quickcheck::{empty_shrinker, Arbitrary, Gen};
use rand::random;

use crate::simulation::{
    model::{Config, Input, Op},
    START_TIME,
};

impl Arbitrary for Config {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut batch_size_limits = [max(u8::arbitrary(g), 1), max(u8::arbitrary(g), 1)];
        batch_size_limits.sort();

        let mut aggregation_job_size_limits = [max(u8::arbitrary(g), 1), max(u8::arbitrary(g), 1)];
        aggregation_job_size_limits.sort();

        let time_precision = Duration::from_seconds(3600);

        Self {
            time_precision,
            min_batch_size: batch_size_limits[0].into(),
            max_batch_size: bool::arbitrary(g).then_some(batch_size_limits[1].into()),
            batch_time_window_size: bool::arbitrary(g).then_some(Duration::from_seconds(
                u64::from(max(u8::arbitrary(g), 1)) * time_precision.as_seconds(),
            )),
            report_expiry_age: bool::arbitrary(g)
                .then_some(Duration::from_seconds(u16::arbitrary(g).into())),
            min_aggregation_job_size: aggregation_job_size_limits[0].into(),
            max_aggregation_job_size: aggregation_job_size_limits[1].into(),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let mut choices = Vec::with_capacity(3);
        if self.max_batch_size.is_some() {
            choices.push(Self {
                max_batch_size: None,
                ..self.clone()
            });
        }
        if self.batch_time_window_size.is_some() {
            choices.push(Self {
                batch_time_window_size: None,
                ..self.clone()
            });
        }
        if self.report_expiry_age.is_some() {
            choices.push(Self {
                report_expiry_age: None,
                ..self.clone()
            });
        }
        Box::new(choices.into_iter())
    }
}

#[derive(Debug, Clone)]
pub(super) struct TimeIntervalInput(pub(super) Input);

#[derive(Debug, Clone)]
pub(super) struct FixedSizeInput(pub(super) Input);

#[derive(Debug, Clone)]
pub(super) struct TimeIntervalFaultInjectionInput(pub(super) Input);

#[derive(Debug, Clone)]
pub(super) struct FixedSizeFaultInjectionInput(pub(super) Input);

#[derive(Debug, Clone)]
pub(super) struct KeyRotatorInput(pub(super) Input);

/// This models the effect that the operations generated so far have on the simulation, and it is
/// used when generating subsequent operations.
struct Context {
    current_time: Time,
    time_precision: Duration,
    started_collection_job_ids: Vec<CollectionJobId>,
    polled_collection_job_ids: Vec<CollectionJobId>,
}

impl Context {
    fn new(config: &Config) -> Self {
        Self {
            current_time: START_TIME,
            time_precision: config.time_precision,
            started_collection_job_ids: Vec::new(),
            polled_collection_job_ids: Vec::new(),
        }
    }

    fn update(&mut self, op: &Op) {
        match op {
            Op::AdvanceTime { amount } => {
                self.current_time = self.current_time.add(amount).unwrap()
            }
            Op::CollectorStart {
                collection_job_id,
                query: _,
            } => self.started_collection_job_ids.push(*collection_job_id),
            Op::CollectorPoll { collection_job_id } => {
                if !self.polled_collection_job_ids.contains(collection_job_id) {
                    self.polled_collection_job_ids.push(*collection_job_id);
                }
            }
            _ => {}
        }
    }
}

/// This is based on `impl<A: Arbitrary> Arbitrary for Vec<A>`, but allows passing additional
/// context, and switching between multiple functions to generate an `Op`.
fn arbitrary_vec_with_context(
    f: impl Fn(&mut Gen, &Context, &[OpKind]) -> Op,
    g: &mut Gen,
    mut context: Context,
    choices: &[OpKind],
) -> Vec<Op> {
    let vec_size = Vec::<()>::arbitrary(g).len();
    let mut output = Vec::with_capacity(vec_size);
    for _ in 0..vec_size {
        let new_op = f(g, &mut context, choices);
        context.update(&new_op);
        output.push(new_op);
    }
    output
}

/// Shrink a vector of operations.
///
/// Since `Op` doesn't implement `Arbitrary` itself, we first wrap them in a newtype that does, and
/// then dispatch to the blanket shrinking implementation for `Vec<impl Arbitrary>`. This will
/// shrink the input list of operations by removing operations, and use a helper function to shrink
/// individual operations themselves.
fn shrink_ops(ops: &[Op]) -> Box<dyn Iterator<Item = Vec<Op>>> {
    #[derive(Clone)]
    struct Wrapper(Op);

    impl Arbitrary for Wrapper {
        fn arbitrary(_g: &mut Gen) -> Self {
            unimplemented!()
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(shrink_op(&self.0).map(Wrapper))
        }
    }

    Box::new(
        ops.iter()
            .map(|op| Wrapper(op.clone()))
            .collect::<Vec<Wrapper>>()
            .shrink()
            .map(|ops| ops.iter().map(|wrapped| wrapped.0.clone()).collect()),
    )
}

fn shrink_op(op: &Op) -> Box<dyn Iterator<Item = Op>> {
    match op {
        Op::AdvanceTime { amount: _ }
        | Op::UploadReplay { report_time: _ }
        | Op::UploadNotRounded { report_time: _ }
        | Op::UploadInvalid { report_time: _ }
        | Op::LeaderGarbageCollector
        | Op::HelperGarbageCollector
        | Op::LeaderKeyRotator
        | Op::HelperKeyRotator
        | Op::AggregationJobCreator
        | Op::AggregationJobDriver
        | Op::AggregationJobDriverRequestError
        | Op::AggregationJobDriverResponseError
        | Op::CollectionJobDriver
        | Op::CollectionJobDriverRequestError
        | Op::CollectionJobDriverResponseError
        | Op::CollectorStart {
            collection_job_id: _,
            query: _,
        }
        | Op::CollectorPoll {
            collection_job_id: _,
        } => empty_shrinker(),

        Op::Upload {
            report_time: _,
            count: 0 | 1,
        } => empty_shrinker(),
        Op::Upload { report_time, count } => Box::new(
            [
                Op::Upload {
                    report_time: *report_time,
                    count: *count / 2,
                },
                Op::Upload {
                    report_time: *report_time,
                    count: *count - 1,
                },
            ]
            .into_iter(),
        ),
    }
}

/// Generate an upload operation.
fn arbitrary_upload_op(g: &mut Gen, context: &Context) -> Op {
    Op::Upload {
        report_time: arbitrary_report_time(g, context),
        count: max(u8::arbitrary(g) & 0xf, 1),
    }
}

/// Generate a replayed upload operation.
fn arbitrary_upload_replay_op(g: &mut Gen, context: &Context) -> Op {
    Op::UploadReplay {
        report_time: arbitrary_report_time(g, context),
    }
}

/// Generate an upload operation, wherein the report timestamp does not get rounded by the client.
fn arbitrary_upload_not_rounded_op(g: &mut Gen, context: &Context) -> Op {
    Op::UploadNotRounded {
        report_time: arbitrary_report_time(g, context),
    }
}

/// Generate an operation to upload an invalid report.
fn arbitrary_upload_invalid_op(g: &mut Gen, context: &Context) -> Op {
    Op::UploadInvalid {
        report_time: arbitrary_report_time(g, context),
    }
}

/// Generate a random report time for an upload operation. The distribution has extra weight on the
/// current time, because very new or very old reports should be rejected, and thus don't exercise
/// much functionality.
fn arbitrary_report_time(g: &mut Gen, context: &Context) -> Time {
    if u8::arbitrary(g) >= 8 {
        // now
        context.current_time
    } else if bool::arbitrary(g) {
        // future
        context
            .current_time
            .add(&Duration::from_seconds(u16::arbitrary(g).into()))
            .unwrap()
    } else {
        // past
        context
            .current_time
            .sub(&Duration::from_seconds(u16::arbitrary(g).into()))
            .unwrap()
    }
}

/// Generate a collect start operation, using a time interval query.
fn arbitrary_collector_start_op_time_interval(g: &mut Gen, context: &Context) -> Op {
    let start_to_now = context.current_time.difference(&START_TIME).unwrap();
    let random_range = start_to_now.as_seconds() / context.time_precision.as_seconds() + 10;
    let start = START_TIME
        .add(&Duration::from_seconds(
            u64::arbitrary(g) % random_range * context.time_precision.as_seconds(),
        ))
        .unwrap();

    let duration_fn = g
        .choose(&[
            (|_g: &mut Gen, context: &Context| -> Duration { context.time_precision })
                as fn(&mut Gen, &Context) -> Duration,
            (|g: &mut Gen, context: &Context| -> Duration {
                Duration::from_seconds(
                    context.time_precision.as_seconds() * (1 + u64::from(u8::arbitrary(g) & 0x1f)),
                )
            }) as fn(&mut Gen, &Context) -> Duration,
        ])
        .unwrap();
    Op::CollectorStart {
        collection_job_id: random(),
        query: super::model::Query::TimeInterval(
            Interval::new(start, duration_fn(g, context)).unwrap(),
        ),
    }
}

fn arbitrary_collector_start_op_fixed_size(g: &mut Gen, context: &Context) -> Op {
    if context.polled_collection_job_ids.is_empty() || bool::arbitrary(g) {
        Op::CollectorStart {
            collection_job_id: random(),
            query: super::model::Query::FixedSizeCurrentBatch,
        }
    } else {
        Op::CollectorStart {
            collection_job_id: random(),
            query: super::model::Query::FixedSizeByBatchId(
                *g.choose(&context.polled_collection_job_ids).unwrap(),
            ),
        }
    }
}

/// Generate a collect poll operation.
fn arbitrary_collector_poll_op(g: &mut Gen, context: &Context) -> Op {
    Op::CollectorPoll {
        collection_job_id: g
            .choose(&context.started_collection_job_ids)
            .copied()
            .unwrap_or_else(|| {
                CollectionJobId::try_from([0u8; CollectionJobId::LEN].as_slice()).unwrap()
            }),
    }
}

impl Arbitrary for TimeIntervalInput {
    fn arbitrary(g: &mut Gen) -> Self {
        let config = Config::arbitrary(g);
        let context = Context::new(&config);
        let ops = arbitrary_vec_with_context(
            arbitrary_op_time_interval,
            g,
            context,
            choices::OP_KIND_CHOICES,
        );
        Self(Input {
            is_fixed_size: false,
            config,
            ops,
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        shrink_input(&self.0, Self)
    }
}

enum OpKind {
    AdvanceTime,
    Upload,
    UploadReplay,
    UploadNotRounded,
    UploadInvalid,
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
    CollectorStart,
    CollectorPoll,
}

/// Arrays of kinds of operations. These will be used with [`Gen::choice`] to select random
/// operations. Some operations are listed multiple times to bias operation selection.
mod choices {
    use super::{OpKind, OpKind::*};
    pub(super) static OP_KIND_CHOICES: &[OpKind] = &[
        AdvanceTime,
        Upload,
        Upload,
        Upload,
        Upload,
        UploadReplay,
        UploadNotRounded,
        UploadInvalid,
        LeaderGarbageCollector,
        HelperGarbageCollector,
        LeaderKeyRotator,
        HelperKeyRotator,
        AggregationJobCreator,
        AggregationJobDriver,
        CollectionJobDriver,
        CollectorStart,
        CollectorPoll,
    ];
    pub(super) static OP_KIND_CHOICES_FAULT_INJECTION: &[OpKind] = &[
        AdvanceTime,
        Upload,
        Upload,
        Upload,
        Upload,
        UploadReplay,
        UploadNotRounded,
        UploadInvalid,
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
        CollectorStart,
        CollectorPoll,
    ];
    pub(super) static OP_KIND_CHOICES_KEY_ROTATOR: &[OpKind] = &[AdvanceTime, LeaderKeyRotator];
}

/// Generate an operation, using time interval queries.
fn arbitrary_op_time_interval(g: &mut Gen, context: &Context, choices: &[OpKind]) -> Op {
    match g.choose(choices).unwrap() {
        OpKind::AdvanceTime => Op::AdvanceTime {
            amount: Duration::from_seconds(u16::arbitrary(g).into()),
        },
        OpKind::Upload => arbitrary_upload_op(g, context),
        OpKind::UploadReplay => arbitrary_upload_replay_op(g, context),
        OpKind::UploadNotRounded => arbitrary_upload_not_rounded_op(g, context),
        OpKind::UploadInvalid => arbitrary_upload_invalid_op(g, context),
        OpKind::LeaderGarbageCollector => Op::LeaderGarbageCollector,
        OpKind::HelperGarbageCollector => Op::HelperGarbageCollector,
        OpKind::LeaderKeyRotator => Op::LeaderKeyRotator,
        OpKind::HelperKeyRotator => Op::HelperKeyRotator,
        OpKind::AggregationJobCreator => Op::AggregationJobCreator,
        OpKind::AggregationJobDriver => Op::AggregationJobDriver,
        OpKind::AggregationJobDriverRequestError => Op::AggregationJobDriverRequestError,
        OpKind::AggregationJobDriverResponseError => Op::AggregationJobDriverResponseError,
        OpKind::CollectionJobDriver => Op::CollectionJobDriver,
        OpKind::CollectionJobDriverRequestError => Op::CollectionJobDriverRequestError,
        OpKind::CollectionJobDriverResponseError => Op::CollectionJobDriverResponseError,
        OpKind::CollectorStart => arbitrary_collector_start_op_time_interval(g, context),
        OpKind::CollectorPoll => arbitrary_collector_poll_op(g, context),
    }
}

impl Arbitrary for FixedSizeInput {
    fn arbitrary(g: &mut Gen) -> Self {
        let config = Config::arbitrary(g);
        let context = Context::new(&config);
        let ops = arbitrary_vec_with_context(
            arbitrary_op_fixed_size,
            g,
            context,
            choices::OP_KIND_CHOICES,
        );
        Self(Input {
            is_fixed_size: true,
            config,
            ops,
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        shrink_input(&self.0, Self)
    }
}

/// Generate an operation, using fixed size queries.
fn arbitrary_op_fixed_size(g: &mut Gen, context: &Context, choices: &[OpKind]) -> Op {
    match g.choose(choices).unwrap() {
        OpKind::AdvanceTime => Op::AdvanceTime {
            amount: Duration::from_seconds(u16::arbitrary(g).into()),
        },
        OpKind::Upload => arbitrary_upload_op(g, context),
        OpKind::UploadReplay => arbitrary_upload_replay_op(g, context),
        OpKind::UploadNotRounded => arbitrary_upload_not_rounded_op(g, context),
        OpKind::UploadInvalid => arbitrary_upload_invalid_op(g, context),
        OpKind::LeaderGarbageCollector => Op::LeaderGarbageCollector,
        OpKind::HelperGarbageCollector => Op::HelperGarbageCollector,
        OpKind::LeaderKeyRotator => Op::LeaderKeyRotator,
        OpKind::HelperKeyRotator => Op::HelperKeyRotator,
        OpKind::AggregationJobCreator => Op::AggregationJobCreator,
        OpKind::AggregationJobDriver => Op::AggregationJobDriver,
        OpKind::AggregationJobDriverRequestError => Op::AggregationJobDriverRequestError,
        OpKind::AggregationJobDriverResponseError => Op::AggregationJobDriverResponseError,
        OpKind::CollectionJobDriver => Op::CollectionJobDriver,
        OpKind::CollectionJobDriverRequestError => Op::CollectionJobDriverRequestError,
        OpKind::CollectionJobDriverResponseError => Op::CollectionJobDriverResponseError,
        OpKind::CollectorStart => arbitrary_collector_start_op_fixed_size(g, context),
        OpKind::CollectorPoll => arbitrary_collector_poll_op(g, context),
    }
}

impl Arbitrary for TimeIntervalFaultInjectionInput {
    fn arbitrary(g: &mut Gen) -> Self {
        let config = Config::arbitrary(g);
        let context = Context::new(&config);
        let ops = arbitrary_vec_with_context(
            arbitrary_op_time_interval,
            g,
            context,
            choices::OP_KIND_CHOICES_FAULT_INJECTION,
        );
        Self(Input {
            is_fixed_size: false,
            config,
            ops,
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        shrink_input(&self.0, Self)
    }
}

impl Arbitrary for FixedSizeFaultInjectionInput {
    fn arbitrary(g: &mut Gen) -> Self {
        let config = Config::arbitrary(g);
        let context = Context::new(&config);
        let ops = arbitrary_vec_with_context(
            arbitrary_op_fixed_size,
            g,
            context,
            choices::OP_KIND_CHOICES_FAULT_INJECTION,
        );
        Self(Input {
            is_fixed_size: true,
            config,
            ops,
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        shrink_input(&self.0, Self)
    }
}

impl Arbitrary for KeyRotatorInput {
    fn arbitrary(g: &mut Gen) -> Self {
        let config = Config::arbitrary(g);
        let context = Context::new(&config);
        let ops = arbitrary_vec_with_context(
            arbitrary_op_time_interval,
            g,
            context,
            choices::OP_KIND_CHOICES_KEY_ROTATOR,
        );
        Self(Input {
            is_fixed_size: false,
            config,
            ops,
        })
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        shrink_input(&self.0, Self)
    }
}

fn shrink_input<T>(input: &Input, constructor: fn(Input) -> T) -> Box<dyn Iterator<Item = T>>
where
    T: 'static,
{
    let with_shrunk_ops = shrink_ops(&input.ops).map({
        let config = input.config.clone();
        let is_fixed_size = input.is_fixed_size;
        move |ops| {
            constructor(Input {
                config: config.clone(),
                ops,
                is_fixed_size,
            })
        }
    });
    let with_shrunk_config = input.config.shrink().map({
        let is_fixed_size = input.is_fixed_size;
        let ops = input.ops.clone();
        move |config| {
            constructor(Input {
                is_fixed_size,
                config,
                ops: ops.clone(),
            })
        }
    });
    Box::new(
        with_shrunk_ops
            .chain(with_shrunk_config)
            .chain(CoalesceOps::new(input.clone(), constructor)),
    )
}

/// Shrinking iterator that coalesces adjacent operations, if possible.
struct CoalesceOps<T> {
    original_input: Option<Input>,
    constructor: fn(Input) -> T,
}

impl<T> CoalesceOps<T> {
    fn new(input: Input, constructor: fn(Input) -> T) -> Self {
        Self {
            original_input: Some(input),
            constructor,
        }
    }
}

impl<T> Iterator for CoalesceOps<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        let original_input = self.original_input.take()?;
        if !original_input
            .ops
            .windows(2)
            .any(|window| window[0].combine(&window[1]).is_some())
        {
            return None;
        }

        let mut last_op = None;
        let mut ops = Vec::with_capacity(original_input.ops.len());
        for op in original_input.ops.into_iter() {
            if last_op.is_none() {
                last_op = Some(op);
            } else if let Some(combined_op) = last_op.as_ref().unwrap().combine(&op) {
                last_op = Some(combined_op);
            } else {
                ops.extend(last_op.replace(op));
            }
        }
        ops.extend(last_op);
        Some((self.constructor)(Input {
            is_fixed_size: original_input.is_fixed_size,
            config: original_input.config,
            ops,
        }))
    }
}

impl Op {
    /// Combine two operations into one equivalent operation, if possible.
    fn combine(&self, other: &Op) -> Option<Op> {
        match (self, other) {
            (
                Op::AdvanceTime {
                    amount: self_amount,
                },
                Op::AdvanceTime {
                    amount: other_amount,
                },
            ) => self_amount
                .add(other_amount)
                .ok()
                .map(|amount| Op::AdvanceTime { amount }),
            (
                Op::Upload {
                    report_time: self_report_time,
                    count: self_count,
                },
                Op::Upload {
                    report_time: other_report_time,
                    count: other_count,
                },
            ) if self_report_time == other_report_time => Some(Op::Upload {
                report_time: *self_report_time,
                count: self_count + other_count,
            }),
            _ => None,
        }
    }
}

#[test]
fn coalesce_ops_correct() {
    let config = Config::arbitrary(&mut Gen::new(0));
    let cases = [
        (
            Vec::from([Op::AdvanceTime {
                amount: Duration::from_seconds(1),
            }]),
            None,
        ),
        (
            Vec::from([
                Op::AdvanceTime {
                    amount: Duration::from_seconds(1),
                },
                Op::AdvanceTime {
                    amount: Duration::from_seconds(2),
                },
            ]),
            Some(Vec::from([Op::AdvanceTime {
                amount: Duration::from_seconds(3),
            }])),
        ),
        (
            Vec::from([
                Op::AdvanceTime {
                    amount: Duration::from_seconds(1),
                },
                Op::AggregationJobCreator,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(1),
                },
            ]),
            None,
        ),
        (
            Vec::from([
                Op::AdvanceTime {
                    amount: Duration::from_seconds(1),
                },
                Op::AdvanceTime {
                    amount: Duration::from_seconds(2),
                },
                Op::AggregationJobCreator,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(3),
                },
                Op::AdvanceTime {
                    amount: Duration::from_seconds(4),
                },
                Op::AggregationJobDriver,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(5),
                },
                Op::AdvanceTime {
                    amount: Duration::from_seconds(6),
                },
            ]),
            Some(Vec::from([
                Op::AdvanceTime {
                    amount: Duration::from_seconds(3),
                },
                Op::AggregationJobCreator,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(7),
                },
                Op::AggregationJobDriver,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(11),
                },
            ])),
        ),
        (
            Vec::from([
                Op::AggregationJobCreator,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(3),
                },
                Op::AdvanceTime {
                    amount: Duration::from_seconds(4),
                },
                Op::AggregationJobDriver,
            ]),
            Some(Vec::from([
                Op::AggregationJobCreator,
                Op::AdvanceTime {
                    amount: Duration::from_seconds(7),
                },
                Op::AggregationJobDriver,
            ])),
        ),
    ];
    for (input_ops, expected_ops) in cases {
        let opt = CoalesceOps::new(
            Input {
                is_fixed_size: false,
                config: config.clone(),
                ops: input_ops,
            },
            |input| input,
        )
        .next();
        assert_eq!(opt.is_some(), expected_ops.is_some());
        if opt.is_some() {
            assert_eq!(opt.unwrap().ops, expected_ops.unwrap());
        }
    }
}
