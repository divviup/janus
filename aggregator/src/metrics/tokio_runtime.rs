use std::time::Duration;

#[cfg(tokio_unstable)]
use opentelemetry::metrics::Meter;
use opentelemetry::{KeyValue, metrics::MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use tokio::runtime::RuntimeMetrics;

pub(super) fn initialize(runtime_metrics: RuntimeMetrics, meter_provider: &SdkMeterProvider) {
    let meter = meter_provider.meter("tokio-runtime-metrics");

    let num_workers = runtime_metrics.num_workers();

    meter
        .u64_observable_gauge("tokio.thread.worker.count")
        .with_description("Number of runtime worker threads")
        .with_unit("{thread}")
        .with_callback({
            let num_workers_u64 = u64::try_from(num_workers).unwrap_or(u64::MAX);
            move |observer| observer.observe(num_workers_u64, &[])
        })
        .build();

    meter
        .u64_observable_counter("tokio.park")
        .with_description("Total number of times worker threads have parked")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                let mut park_count = 0;
                for worker in 0..num_workers {
                    park_count += runtime_metrics.worker_park_count(worker);
                }
                observer.observe(park_count, &[]);
            }
        })
        .build();

    meter
        .f64_observable_counter("tokio.thread.worker.busy.time")
        .with_description("Total amount of time that all worker threads have been busy")
        .with_unit("s")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                let mut total_busy_duration = Duration::from_secs(0);
                for worker in 0..num_workers {
                    total_busy_duration += runtime_metrics.worker_total_busy_duration(worker);
                }
                observer.observe(total_busy_duration.as_secs_f64(), &[]);
            }
        })
        .build();

    #[cfg(not(tokio_unstable))]
    meter
        .u64_observable_gauge("tokio.queue.depth")
        .with_description("Number of tasks currently in the runtime's global queue")
        .with_unit("{task}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                observer.observe(
                    u64::try_from(runtime_metrics.global_queue_depth()).unwrap_or(u64::MAX),
                    &[KeyValue::new("queue", "global")],
                )
            }
        })
        .build();

    #[cfg(tokio_unstable)]
    initialize_unstable_metrics(runtime_metrics, meter);
}

#[cfg(tokio_unstable)]
fn initialize_unstable_metrics(runtime_metrics: RuntimeMetrics, meter: Meter) {
    let num_workers = runtime_metrics.num_workers();

    meter
        .u64_observable_gauge("tokio.thread.blocking.count")
        .with_description(
            "Number of additional threads spawned by the runtime for blocking operations",
        )
        .with_unit("{thread}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                observer.observe(
                    u64::try_from(runtime_metrics.num_blocking_threads()).unwrap_or(u64::MAX),
                    &[],
                )
            }
        })
        .build();

    meter
        .u64_observable_gauge("tokio.task.alive.count")
        .with_description("Number of alive tasks in the runtime")
        .with_unit("{task}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                observer.observe(
                    u64::try_from(runtime_metrics.num_alive_tasks()).unwrap_or(u64::MAX),
                    &[],
                )
            }
        })
        .build();

    meter
        .u64_observable_gauge("tokio.thread.blocking.idle.count")
        .with_description("Number of additional threads for blocking operations which are idle")
        .with_unit("{thread}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                observer.observe(
                    u64::try_from(runtime_metrics.num_idle_blocking_threads()).unwrap_or(u64::MAX),
                    &[],
                )
            }
        })
        .build();

    meter
        .u64_observable_counter("tokio.task.spawned")
        .with_description("Total number of tasks spawned in the runtime")
        .with_unit("{task}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| observer.observe(runtime_metrics.spawned_tasks_count(), &[])
        })
        .build();

    meter
        .u64_observable_counter("tokio.task.scheduled")
        .with_description(
            "Number of tasks scheduled, either ot the thread's own local queue, \
            from a worker thread to the global queue due to overflow, or \
            from a remote thread to the global queue",
        )
        .with_unit("{task}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                let remote_schedule_count = runtime_metrics.remote_schedule_count();

                let mut local_schedule_count = 0;
                let mut overflow_count = 0;
                for worker in 0..num_workers {
                    local_schedule_count += runtime_metrics.worker_local_schedule_count(worker);
                    overflow_count += runtime_metrics.worker_overflow_count(worker);
                }

                observer.observe(local_schedule_count, &[KeyValue::new("queue", "local")]);
                observer.observe(overflow_count, &[KeyValue::new("queue", "local_overflow")]);
                observer.observe(remote_schedule_count, &[KeyValue::new("queue", "remote")]);
            }
        })
        .build();

    meter
        .u64_observable_counter("tokio.task.budget_forced_yield")
        .with_description(
            "Number of times tasks have been forced to yield because their task budget was \
            exhausted",
        )
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                observer.observe(runtime_metrics.budget_forced_yield_count(), &[]);
            }
        })
        .build();

    meter
        .u64_observable_counter("tokio.noop")
        .with_description(
            "Total number of times worker threads unparked and parked again without doing any work",
        )
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                let mut noop_count = 0;
                for worker in 0..num_workers {
                    noop_count += runtime_metrics.worker_noop_count(worker);
                }
                observer.observe(noop_count, &[]);
            }
        })
        .build();

    meter
        .u64_observable_counter("tokio.task.stolen")
        .with_description("Total number of tasks stolen between worker threads")
        .with_unit("{task}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                let mut steal_count = 0;
                for worker in 0..num_workers {
                    steal_count += runtime_metrics.worker_steal_count(worker);
                }
                observer.observe(steal_count, &[]);
            }
        })
        .build();

    meter
        .u64_observable_counter("tokio.steals")
        .with_description("Nuber of times worker threads successfully stole one or more tasks")
        .with_unit("{operation}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                let mut steal_operations = 0;
                for worker in 0..num_workers {
                    steal_operations += runtime_metrics.worker_steal_operations(worker);
                }
                observer.observe(steal_operations, &[]);
            }
        })
        .build();

    meter
        .u64_observable_gauge("tokio.queue.depth")
        .with_description(
            "Number of tasks currently in the runtime's global queue, blocking thread pool queue, \
            or a worker's local queue",
        )
        .with_unit("{task}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                for worker in 0..num_workers {
                    observer.observe(
                        u64::try_from(runtime_metrics.worker_local_queue_depth(worker))
                            .unwrap_or(u64::MAX),
                        &[
                            KeyValue::new("queue", "local"),
                            KeyValue::new("worker", i64::try_from(worker).unwrap()),
                        ],
                    );
                }
                observer.observe(
                    u64::try_from(runtime_metrics.global_queue_depth()).unwrap_or(u64::MAX),
                    &[KeyValue::new("queue", "global")],
                );
                observer.observe(
                    u64::try_from(runtime_metrics.blocking_queue_depth()).unwrap_or(u64::MAX),
                    &[KeyValue::new("queue", "blocking")],
                );
            }
        })
        .build();

    meter
        .u64_observable_gauge("tokio.io.fd.count")
        .with_description("Number of file descriptors currently registered with the I/O driver")
        .with_unit("{fd}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| {
                observer.observe(
                    runtime_metrics
                        .io_driver_fd_registered_count()
                        .saturating_sub(runtime_metrics.io_driver_fd_deregistered_count()),
                    &[],
                )
            }
        })
        .build();

    meter
        .u64_observable_counter("tokio.io.fd.registered")
        .with_description("Total number of file descriptors registered by the I/O driver")
        .with_unit("{fd}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| observer.observe(runtime_metrics.io_driver_fd_registered_count(), &[])
        })
        .build();

    meter
        .u64_observable_counter("tokio.io.fd.deregistered")
        .with_description("Total number of file descriptors deregistered by the I/O driver")
        .with_unit("{fd}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| observer.observe(runtime_metrics.io_driver_fd_deregistered_count(), &[])
        })
        .build();

    meter
        .u64_observable_counter("tokio.io.ready_events")
        .with_description("Number of ready events processed by the I/O driver")
        .with_unit("{event}")
        .with_callback({
            let runtime_metrics = runtime_metrics.clone();
            move |observer| observer.observe(runtime_metrics.io_driver_ready_count(), &[])
        })
        .build();
}
