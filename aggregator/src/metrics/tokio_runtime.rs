use std::time::{Duration, SystemTime};

use derivative::Derivative;
use opentelemetry::{metrics::MetricsError, InstrumentationLibrary, KeyValue};
use opentelemetry_sdk::metrics::{
    data::{
        DataPoint, Gauge, Histogram, HistogramDataPoint, Metric, ScopeMetrics, Sum, Temporality,
    },
    reader::MetricProducer,
};
use tokio::runtime::{self, HistogramScale, RuntimeMetrics};

use crate::metrics::{HistogramScale as ConfigHistogramScale, TokioMetricsConfiguration};

impl From<ConfigHistogramScale> for HistogramScale {
    fn from(value: ConfigHistogramScale) -> Self {
        match value {
            ConfigHistogramScale::Linear => HistogramScale::Linear,
            ConfigHistogramScale::Log => HistogramScale::Log,
        }
    }
}

pub(crate) fn configure_runtime(
    runtime_builder: &mut runtime::Builder,
    config: &TokioMetricsConfiguration,
) {
    if config.enable_poll_time_histogram {
        runtime_builder.enable_metrics_poll_count_histogram();
        runtime_builder.metrics_poll_count_histogram_scale(config.poll_time_histogram_scale.into());
        if let Some(resolution) = config.poll_time_histogram_resolution_us {
            let resolution = Duration::from_micros(resolution);
            runtime_builder.metrics_poll_count_histogram_resolution(resolution);
        }
        if let Some(buckets) = config.poll_time_histogram_buckets {
            runtime_builder.metrics_poll_count_histogram_buckets(buckets);
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub(super) struct TokioRuntimeMetrics {
    runtime_metrics: RuntimeMetrics,
    #[derivative(Debug = "ignore")]
    scope: InstrumentationLibrary,
    #[derivative(Debug = "ignore")]
    start_time: SystemTime,
    num_workers: usize,
    poll_count_histogram_num_buckets: usize,
    poll_count_histogram_bucket_bounds: Vec<f64>,
    #[derivative(Debug = "ignore")]
    attributes_local: Vec<KeyValue>,
    #[derivative(Debug = "ignore")]
    attributes_local_overflow: Vec<KeyValue>,
    #[derivative(Debug = "ignore")]
    attributes_remote: Vec<KeyValue>,
    #[derivative(Debug = "ignore")]
    attributes_local_queue_worker: Vec<Vec<KeyValue>>,
    attributes_injection_queue: Vec<KeyValue>,
    attributes_blocking_queue: Vec<KeyValue>,
}

impl TokioRuntimeMetrics {
    pub(super) fn new(runtime_metrics: RuntimeMetrics) -> Self {
        let scope = InstrumentationLibrary::builder("tokio-runtime-metrics").build();

        let start_time = SystemTime::now();

        let num_workers = runtime_metrics.num_workers();
        let poll_count_histogram_enabled = runtime_metrics.poll_count_histogram_enabled();
        let poll_count_histogram_num_buckets = runtime_metrics.poll_count_histogram_num_buckets();
        let all_but_last_bucket = if poll_count_histogram_enabled {
            0..poll_count_histogram_num_buckets - 1
        } else {
            0..0
        };
        let poll_count_histogram_bucket_bounds = all_but_last_bucket
            .map(|bucket| {
                runtime_metrics
                    .poll_count_histogram_bucket_range(bucket)
                    .end
                    .as_secs_f64()
            })
            .collect();

        let attributes_local = Vec::from([KeyValue::new("queue", "local")].as_slice());
        let attributes_local_overflow =
            Vec::from([KeyValue::new("queue", "local_overflow")].as_slice());
        let attributes_remote = Vec::from([KeyValue::new("queue", "remote")].as_slice());
        let attributes_local_queue_worker = (0..num_workers)
            .map(|i| {
                Vec::from(
                    [
                        KeyValue::new("queue", "local"),
                        KeyValue::new("worker", i64::try_from(i).unwrap()),
                    ]
                    .as_slice(),
                )
            })
            .collect();
        let attributes_injection_queue =
            Vec::from([KeyValue::new("queue", "injection")].as_slice());
        let attributes_blocking_queue = Vec::from([KeyValue::new("queue", "blocking")].as_slice());

        Self {
            runtime_metrics,
            scope,
            start_time,
            num_workers,
            poll_count_histogram_num_buckets,
            poll_count_histogram_bucket_bounds,
            attributes_local,
            attributes_local_overflow,
            attributes_remote,
            attributes_local_queue_worker,
            attributes_injection_queue,
            attributes_blocking_queue,
        }
    }
}

impl MetricProducer for TokioRuntimeMetrics {
    fn produce(&self) -> Result<ScopeMetrics, MetricsError> {
        let now = SystemTime::now();

        let num_blocking_threads = self.runtime_metrics.num_blocking_threads();
        let num_alive_tasks = self.runtime_metrics.num_alive_tasks();
        let num_idle_blocking_threads = self.runtime_metrics.num_idle_blocking_threads();
        let spawned_task_count = self.runtime_metrics.spawned_tasks_count();
        let remote_schedule_count = self.runtime_metrics.remote_schedule_count();
        let budget_forced_yield_count = self.runtime_metrics.budget_forced_yield_count();
        let injection_queue_depth = self.runtime_metrics.injection_queue_depth();
        let blocking_queue_depth = self.runtime_metrics.blocking_queue_depth();
        let io_driver_fd_registered_count = self.runtime_metrics.io_driver_fd_registered_count();
        let io_driver_fd_deregistered_count =
            self.runtime_metrics.io_driver_fd_deregistered_count();
        let io_driver_ready_count = self.runtime_metrics.io_driver_ready_count();

        let mut park_count = 0;
        let mut noop_count = 0;
        let mut steal_count = 0;
        let mut steal_operations = 0;
        let mut poll_count = 0;
        let mut total_busy_duration = Duration::from_secs(0);
        let mut local_schedule_count = 0;
        let mut overflow_count = 0;
        let mut local_queue_depth = vec![0; self.num_workers];
        let mut poll_count_histogram_bucket_count = vec![0; self.poll_count_histogram_num_buckets];
        let mut worker_mean_poll_time_sum = Duration::from_secs(0);
        for (worker, worker_local_queue_depth) in local_queue_depth.iter_mut().enumerate() {
            park_count += self.runtime_metrics.worker_park_count(worker);
            noop_count += self.runtime_metrics.worker_noop_count(worker);
            steal_count += self.runtime_metrics.worker_steal_count(worker);
            steal_operations += self.runtime_metrics.worker_steal_operations(worker);
            poll_count += self.runtime_metrics.worker_poll_count(worker);
            total_busy_duration += self.runtime_metrics.worker_total_busy_duration(worker);
            local_schedule_count += self.runtime_metrics.worker_local_schedule_count(worker);
            overflow_count += self.runtime_metrics.worker_overflow_count(worker);

            *worker_local_queue_depth = self.runtime_metrics.worker_local_queue_depth(worker);

            for (bucket, out) in poll_count_histogram_bucket_count.iter_mut().enumerate() {
                *out += self
                    .runtime_metrics
                    .poll_count_histogram_bucket_count(worker, bucket);
            }

            worker_mean_poll_time_sum += self.runtime_metrics.worker_mean_poll_time(worker);
        }
        let mean_poll_time = worker_mean_poll_time_sum / u32::try_from(self.num_workers).unwrap();

        let metrics = Vec::from([
            Metric {
                name: "tokio.thread.worker.count".into(),
                description: "Number of runtime worker threads".into(),
                unit: "{thread}".into(),
                data: Box::new(Gauge::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::default(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: u64::try_from(self.num_workers).unwrap_or(u64::MAX),
                        exemplars: Vec::new(),
                    }]),
                }),
            },
            Metric {
                name: "tokio.thread.blocking.count".into(),
                description: "Number of additional threads spawned by the runtime for blocking \
                              operations"
                    .into(),
                unit: "{thread}".into(),
                data: Box::new(Gauge::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: u64::try_from(num_blocking_threads).unwrap_or(u64::MAX),
                        exemplars: Vec::new(),
                    }]),
                }),
            },
            Metric {
                name: "tokio.task.alive.count".into(),
                description: "Number of alive tasks in the runtime".into(),
                unit: "{task}".into(),
                data: Box::new(Gauge::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: u64::try_from(num_alive_tasks).unwrap_or(u64::MAX),
                        exemplars: Vec::new(),
                    }]),
                }),
            },
            Metric {
                name: "tokio.thread.blocking.idle.count".into(),
                description: "Number of additional threads for blocking operations which are idle"
                    .into(),
                unit: "{thread}".into(),
                data: Box::new(Gauge::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: u64::try_from(num_idle_blocking_threads).unwrap_or(u64::MAX),
                        exemplars: Vec::new(),
                    }]),
                }),
            },
            Metric {
                name: "tokio.task.spawned".into(),
                description: "Total number of tasks spawned in the runtime".into(),
                unit: "{task}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: spawned_task_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.task.scheduled".into(),
                description: "Number of tasks scheduled, either to the thread's own local queue, \
                              from a worker thread to the injection queue due to overflow, or \
                              from a remote thread to the injection queue"
                    .into(),
                unit: "{task}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([
                        DataPoint {
                            attributes: self.attributes_local.clone(),
                            start_time: Some(self.start_time),
                            time: Some(now),
                            value: local_schedule_count,
                            exemplars: Vec::new(),
                        },
                        DataPoint {
                            attributes: self.attributes_local_overflow.clone(),
                            start_time: Some(self.start_time),
                            time: Some(now),
                            value: overflow_count,
                            exemplars: Vec::new(),
                        },
                        DataPoint {
                            attributes: self.attributes_remote.clone(),
                            start_time: Some(self.start_time),
                            time: Some(now),
                            value: remote_schedule_count,
                            exemplars: Vec::new(),
                        },
                    ]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.task.budget_forced_yield".into(),
                description: "Number of times tasks have been forced to yield because their task \
                              budget was exhausted"
                    .into(),
                unit: "".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: budget_forced_yield_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.park".into(),
                description: "Total number of times worker threads have parked".into(),
                unit: "".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: park_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.noop".into(),
                description: "Total number of times worker threads unparked and parked again \
                              without doing any work"
                    .into(),
                unit: "".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: noop_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.task.stolen".into(),
                description: "Total number of tasks stolen between worker threads".into(),
                unit: "{task}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: steal_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.steals".into(),
                description: "Number of times worker threads successfully stole one or more tasks"
                    .into(),
                unit: "{operation}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: steal_operations,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.thread.worker.busy.time".into(),
                description: "Total amount of time that all worker threads have been busy".into(),
                unit: "s".into(),
                data: Box::new(Sum::<f64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: total_busy_duration.as_secs_f64(),
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.queue.depth".into(),
                description: "Number of tasks currently in the runtime's injection queue, \
                              blocking thread pool queue, or a worker's local queue"
                    .into(),
                unit: "{task}".into(),
                data: Box::new(Gauge::<u64> {
                    data_points: {
                        let mut data_points = Vec::with_capacity(self.num_workers + 2);
                        data_points.extend(
                            local_queue_depth
                                .into_iter()
                                .zip(self.attributes_local_queue_worker.iter())
                                .map(|(worker_local_queue_depth, attributes)| DataPoint {
                                    attributes: attributes.clone(),
                                    start_time: Some(self.start_time),
                                    time: Some(now),
                                    value: u64::try_from(worker_local_queue_depth)
                                        .unwrap_or(u64::MAX),
                                    exemplars: Vec::new(),
                                }),
                        );
                        data_points.push(DataPoint {
                            attributes: self.attributes_injection_queue.clone(),
                            start_time: Some(self.start_time),
                            time: Some(now),
                            value: u64::try_from(injection_queue_depth).unwrap_or(u64::MAX),
                            exemplars: Vec::new(),
                        });
                        data_points.push(DataPoint {
                            attributes: self.attributes_blocking_queue.clone(),
                            start_time: Some(self.start_time),
                            time: Some(now),
                            value: u64::try_from(blocking_queue_depth).unwrap_or(u64::MAX),
                            exemplars: Vec::new(),
                        });
                        data_points
                    },
                }),
            },
            Metric {
                name: "tokio.task.poll.time".into(),
                description: "Histogram of task poll times".into(),
                unit: "s".into(),
                data: Box::new(Histogram::<f64> {
                    data_points: Vec::from([HistogramDataPoint {
                        attributes: Vec::new(),
                        start_time: self.start_time,
                        time: now,
                        count: poll_count,
                        bounds: self.poll_count_histogram_bucket_bounds.clone(),
                        bucket_counts: poll_count_histogram_bucket_count,
                        min: Some(f64::NAN),
                        max: Some(f64::NAN),
                        sum: f64::NAN,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                }),
            },
            Metric {
                name: "tokio.task.poll.time.average".into(),
                description: "Exponentially weighted moving average of task poll times".into(),
                unit: "s".into(),
                data: Box::new(Gauge::<f64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: mean_poll_time.as_secs_f64(),
                        exemplars: Vec::new(),
                    }]),
                }),
            },
            Metric {
                name: "tokio.io.fd.count".into(),
                description: "Number of file descriptors currently registered with the I/O driver"
                    .into(),
                unit: "{fd}".into(),
                data: Box::new(Gauge::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: io_driver_fd_registered_count
                            .saturating_sub(io_driver_fd_deregistered_count),
                        exemplars: Vec::new(),
                    }]),
                }),
            },
            Metric {
                name: "tokio.io.fd.registered".into(),
                description: "Total number of file descriptors registered by the I/O driver".into(),
                unit: "{fd}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: io_driver_fd_registered_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.io.fd.deregistered".into(),
                description: "Total number of file descriptors deregistered by the I/O driver"
                    .into(),
                unit: "{fd}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: io_driver_fd_deregistered_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
            Metric {
                name: "tokio.io.ready_events".into(),
                description: "Number of ready events processed by the I/O driver".into(),
                unit: "{event}".into(),
                data: Box::new(Sum::<u64> {
                    data_points: Vec::from([DataPoint {
                        attributes: Vec::new(),
                        start_time: Some(self.start_time),
                        time: Some(now),
                        value: io_driver_ready_count,
                        exemplars: Vec::new(),
                    }]),
                    temporality: Temporality::Cumulative,
                    is_monotonic: true,
                }),
            },
        ]);
        Ok(ScopeMetrics {
            scope: self.scope.clone(),
            metrics,
        })
    }
}
