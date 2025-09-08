use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use itertools::Itertools;
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, MetricsError},
    KeyValue,
};
use tokio::{
    select,
    sync::{
        mpsc,
        oneshot::{self},
        OwnedSemaphorePermit, Semaphore,
    },
    task::JoinHandle,
};
use tracing::{debug, error, warn};
use trillium::{Conn, Handler};
use trillium_macros::Handler;

use super::Error;

/// A queue that services requests in an _approximately_ LIFO manner, i.e. the most recent request
/// is serviced first. It bounds the total number of waiting requests, and the number of requests
/// that can be run concurrently. This is useful for adding backpressure and preventing the process
/// from being overwhelmed.
///
/// See https://encore.dev/blog/queueing for a rationale of LIFO request queuing.
///
/// Note the actual execution order of requests is not perfectly LIFO if the concurrency is >1,
/// because the order that request futures are scheduled and executed in is essentially
/// non-deterministic.
#[derive(Debug)]
pub struct LIFORequestQueue {
    /// Sends messages to the dispatcher task.
    dispatcher_tx: mpsc::UnboundedSender<DispatcherMessage>,

    /// Used to generate unique request IDs for identifying requests in the queue. Request numbers
    /// are unique as long as this counter doesn't overflow, which shouldn't happen under practical
    /// usage. For instance, it takes approximately 584,000 years at 1M QPS to overflow a 64-bit
    /// counter.
    id_counter: AtomicU64,

    /// Maximum time a request can wait in the queue.
    request_timeout: Option<Duration>,

    /// Metrics for monitoring queue behavior.
    metrics: Metrics,
}

impl LIFORequestQueue {
    /// Creates a new [`Self`].
    ///
    /// `concurrency` must be greater than zero.
    ///
    /// `meter_prefix` is a string to disambiguate one queue from another in the metrics, while
    /// using the same meter. All metric names will be prefixed with this string.
    ///
    /// `request_timeout` specifies the maximum time a request can wait in the queue.
    pub fn new(
        concurrency: u32,
        depth: usize,
        meter: &Meter,
        meter_prefix: &str,
        request_timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        if concurrency < 1 {
            return Err(Error::InvalidConfiguration(
                "concurrency must be greater than 0",
            ));
        }

        let (message_tx, message_rx) = mpsc::unbounded_channel();
        let id_counter = Default::default();
        let max_outstanding_requests =
            u64::try_from(usize::try_from(concurrency).unwrap() + depth).unwrap();
        let metrics = Metrics::new(meter, meter_prefix, max_outstanding_requests)
            .map_err(|e| Error::Internal(e.to_string()))?;
        Self::dispatcher(message_rx, concurrency, depth, metrics.clone());

        Ok(Self {
            id_counter,
            dispatcher_tx: message_tx,
            metrics,
            request_timeout,
        })
    }

    /// Spawns a task that dispatches permits to waiting requests. Once a permit is dispatched, the
    /// request may proceed.
    ///
    /// Requests are dispatched in LIFO-order. An incoming request will either immediately receive
    /// an [`OwnedSemaphorePermit`], be placed at the head of the queue, or be rejected if there's
    /// no space in the queue.
    ///
    /// Permits are returned to the dispatcher automatically when the [`OwnedSemaphorePermit`] is
    /// dropped, allowing other requests to be dispatched.
    fn dispatcher(
        mut dispatcher_rx: mpsc::UnboundedReceiver<DispatcherMessage>,
        concurrency: u32,
        depth: usize,
        metrics: Metrics,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Use a BTreeMap to allow for cancellation (i.e. removal) of waiting requests in
            // sublinear time, and to maintain LIFO ordering by ID.
            let mut stack: BTreeMap<u64, PermitTx> = BTreeMap::new();

            // Unwrap safety: conversion only fails on architectures where usize is less than
            // 32-bits.
            let semaphore = Arc::new(Semaphore::new(concurrency.try_into().unwrap()));

            // Create a collection of permits which we'll dispatch to requests.
            // Unwrap safety: the semaphore is never closed.
            let mut permits = Arc::clone(&semaphore)
                .acquire_many_owned(concurrency)
                .await
                .unwrap();

            loop {
                let semaphore = Arc::clone(&semaphore);
                select! {
                    recv = dispatcher_rx.recv() => {
                        match recv {
                            Some(message) => {
                                match message {
                                    DispatcherMessage::Enqueue(id, permit_tx) => {
                                        if let Some(permit) = permits.split(1) {
                                            permit_tx.send(Ok(permit));
                                            metrics.requests_processed_immediately.add(1, &[]);
                                        } else if stack.len() < depth {
                                            if stack.insert(id, permit_tx).is_some() {
                                                // Avoid panicking on this bug, since if this
                                                // process dies, request processing stops.
                                                error!(?id, "bug: overwrote existing request in the queue");
                                                metrics.requests_queued.add(1, &[KeyValue::new("status", "overwrote")]);
                                            } else {
                                                metrics.requests_queued.add(1, &[]);
                                            }
                                        } else {
                                            permit_tx.send(Err(Error::TooManyRequests));
                                            metrics.requests_rejected.add(1, &[]);
                                        }
                                    },
                                    DispatcherMessage::Cancel(id) => {
                                        debug!(?id, "removing request from the queue");
                                        if stack.remove(&id).is_some() {
                                            metrics.requests_cancelled.add(1, &[]);
                                        }
                                    },
                                }
                            }
                            // The receiver is held open for at least the life of the LIFORequestQueue
                            // by the stored dispatcher_rx. If that's been dropped, and all other
                            // message senders have been dropped (one each is cloned to requests
                            // for cancellation), then the dispatcher can be closed.
                            None => {
                                debug!("dispatcher receiver closed, shutting down dispatcher");
                                return;
                            }
                        }
                    }

                    Ok(permit) = semaphore.acquire_owned() => {
                        // pop_last() pops the element maximum valued element. The request ID
                        // counter is _mostly_ monotonically incrementing, so the highest ID will
                        // be the most recent request, giving us LIFO semantics.
                        //
                        // This property isn't preserved when the ID generator overflows, but that
                        // is not a practical concern. See [`Self::id_counter`].
                        match stack.pop_last() {
                            Some((_, permit_tx)) => {
                                permit_tx.send(Ok(permit));
                                metrics.requests_dequeued.add(1, &[]);
                            }
                            None => permits.merge(permit),
                        }
                    }
                }

                // Unwrap safety: only fails on architectures where usize is less than 32 bits, or
                // greater than 64 bits.
                metrics.outstanding_requests.store(
                    (stack.len() + usize::try_from(concurrency).unwrap() - permits.num_permits())
                        .try_into()
                        .unwrap(),
                    Ordering::Relaxed,
                );
                metrics
                    .stacked_requests
                    .store(u64::try_from(stack.len()).unwrap(), Ordering::Relaxed);
            }
        })
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, Error> {
        let id = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let (permit_tx, permit_rx) = oneshot::channel();

        let enqueue_time = Instant::now();
        self.dispatcher_tx
            .send(DispatcherMessage::Enqueue(id, PermitTx(permit_tx)))
            // We don't necessarily panic because the dispatcher task could be shutdown as part of
            // process shutdown, while a request is in flight.
            .map_err(|_| Error::Internal("dispatcher task died".to_string()))?;

        /// Sends a cancellation message over the given channel when the guard is dropped, unless
        /// [`Self::disarm`] is called.
        struct CancelDropGuard {
            id: u64,
            sender: mpsc::UnboundedSender<DispatcherMessage>,
            armed: bool,
            metrics: Metrics,
            enqueue_time: Instant,
        }

        impl CancelDropGuard {
            fn new(
                id: u64,
                sender: mpsc::UnboundedSender<DispatcherMessage>,
                metrics: Metrics,
                enqueue_time: Instant,
            ) -> Self {
                Self {
                    id,
                    sender,
                    armed: true,
                    metrics,
                    enqueue_time,
                }
            }

            fn disarm(&mut self) {
                self.armed = false;
            }
        }

        impl Drop for CancelDropGuard {
            fn drop(&mut self) {
                if self.armed {
                    self.metrics.wait_time_histogram.record(
                        self.enqueue_time.elapsed().as_secs_f64(),
                        &[KeyValue::new("status", "cancelled")],
                    );
                    let _ = self
                        .sender
                        .send(DispatcherMessage::Cancel(self.id))
                        .map_err(|err| warn!("failed to send cancellation message: {:?}", err));
                }
            }
        }

        let mut drop_guard = CancelDropGuard::new(
            id,
            self.dispatcher_tx.clone(),
            self.metrics.clone(),
            enqueue_time,
        );

        let permit_future = async {
            let permit = permit_rx.await;
            drop_guard.disarm();

            self.metrics.wait_time_histogram.record(
                enqueue_time.elapsed().as_secs_f64(),
                &[KeyValue::new("status", "dequeued")],
            );

            // If the rx channel is prematurely dropped, we'll reach this error, indicating that
            // something has gone wrong with the dispatcher task or it has shutdown. If the drop guard
            // causes the rx channel to be dropped, we shouldn't reach this error because the overall
            // future would have been dropped.
            permit.map_err(|_| Error::Internal("rx channel dropped".to_string()))?
        };

        // If a request timeout is provided, impose it. If not, use the original release/0.7
        // logic.
        match self.request_timeout {
            Some(timeout) => tokio::time::timeout(timeout, permit_future)
                .await
                .map_err(|_| {
                    self.metrics.requests_timeout_queue.add(1, &[]);
                    Error::RequestTimeout
                })?,
            None => permit_future.await,
        }
    }
}

/// Messages for communicating with the dispatcher task.
#[derive(Debug)]
enum DispatcherMessage {
    /// A new request has arrived.
    Enqueue(u64, PermitTx),

    /// A request has reneged, likely because the connection has timed out, so remove the request
    /// from the queue.
    Cancel(u64),
}

/// Dispatcher-side permit sender channel. May receive failure if the queue is full.
#[derive(Debug)]
struct PermitTx(oneshot::Sender<Result<OwnedSemaphorePermit, Error>>);

impl PermitTx {
    fn send(self, result: Result<OwnedSemaphorePermit, Error>) {
        let _ = self
            .0
            .send(result)
            .map_err(|_| warn!("failed to dispatch, request cancelled?"));
    }
}

/// A handler that queues requests in a LIFO manner, according to the parameters set in a
/// [`LIFORequestQueue`].
///
/// Multiple request handlers can share a queue, by cloning the [`Arc`] that wraps the queue.
#[derive(Handler)]
pub struct LIFOQueueHandler<H> {
    #[handler(except = [run])]
    handler: H,
    queue: Arc<LIFORequestQueue>,
}

impl<H: Handler> LIFOQueueHandler<H> {
    pub fn new(queue: Arc<LIFORequestQueue>, handler: H) -> Self {
        Self { handler, queue }
    }

    async fn run(&self, mut conn: Conn) -> Conn {
        match conn.cancel_on_disconnect(self.queue.acquire()).await {
            Some(permit) => match permit {
                Ok(_permit) => self.handler.run(conn).await,
                Err(err) => err.run(conn).await,
            },
            None => Error::ClientDisconnected.run(conn).await,
        }
    }
}

/// Convenience function for wrapping a handler with a [`LIFOQueueHandler`].
pub fn queued_lifo<H: Handler>(queue: Arc<LIFORequestQueue>, handler: H) -> impl Handler {
    LIFOQueueHandler::new(queue, handler)
}

#[derive(Clone, Debug)]
struct Metrics {
    /// The approximate number of requests currently being serviced by the queue. It's approximate
    /// since the queue length may have changed before the measurement is taken. In practice, the
    /// error should only be +/- 1. It is also more or less suitable for synchronization during
    /// tests.
    outstanding_requests: Arc<AtomicU64>,

    /// Number of requests currently waiting in the queue.
    stacked_requests: Arc<AtomicU64>,

    /// Histogram measuring how long a queue item waited before being dequeued.
    wait_time_histogram: Histogram<f64>,

    /// Counter for requests processed immediately without queueing.
    requests_processed_immediately: Counter<u64>,

    /// Counter for requests that were queued.
    requests_queued: Counter<u64>,

    /// Counter for requests that were dequeued and started processing.
    requests_dequeued: Counter<u64>,

    /// Counter for requests that were rejected due to queue being full.
    requests_rejected: Counter<u64>,

    /// Counter for requests that were cancelled.
    requests_cancelled: Counter<u64>,

    /// Counter for requests that timed out while waiting in the queue.
    requests_timeout_queue: Counter<u64>,
}

impl Metrics {
    const OUTSTANDING_REQUESTS_METRIC_NAME: &'static str = "outstanding_requests";
    const MAX_OUTSTANDING_REQUESTS_METRIC_NAME: &'static str = "max_outstanding_requests";
    const STACKED_REQUESTS_METRIC_NAME: &'static str = "stacked_requests";
    const WAIT_TIME_METRIC_NAME: &'static str = "lifo_queue_wait_time";
    const REQUESTS_PROCESSED_IMMEDIATELY_METRIC_NAME: &'static str =
        "requests_processed_immediately";
    const REQUESTS_QUEUED_METRIC_NAME: &'static str = "requests_queued";
    const REQUESTS_DEQUEUED_METRIC_NAME: &'static str = "requests_dequeued";
    const REQUESTS_REJECTED_METRIC_NAME: &'static str = "requests_rejected";
    const REQUESTS_CANCELLED_METRIC_NAME: &'static str = "requests_cancelled";
    const REQUESTS_TIMEOUT_QUEUE_METRIC_NAME: &'static str = "requests_timeout_queue";

    fn metric_name(prefix: &str, name: &str) -> String {
        [prefix, name].into_iter().join("_")
    }

    fn new(
        meter: &Meter,
        prefix: &str,
        max_outstanding_requests: u64,
    ) -> Result<Self, MetricsError> {
        let outstanding_requests = Arc::new(AtomicU64::new(0));
        let stacked_requests = Arc::new(AtomicU64::new(0));

        let outstanding_requests_gauge = meter
            .u64_observable_gauge(Self::metric_name(
                prefix,
                Self::OUTSTANDING_REQUESTS_METRIC_NAME,
            ))
            .with_description(
                "The approximate number of requests currently being serviced by the aggregator.",
            )
            .with_unit("{request}")
            .init();
        let max_outstanding_requests_gauge = meter
            .u64_observable_gauge(Self::metric_name(
                prefix,
                Self::MAX_OUTSTANDING_REQUESTS_METRIC_NAME,
            ))
            .with_description(
                "The maximum number of requests that the aggregator can service at a time.",
            )
            .with_unit("{request}")
            .init();

        meter.register_callback(
            &[
                outstanding_requests_gauge.as_any(),
                max_outstanding_requests_gauge.as_any(),
            ],
            {
                let outstanding_requests = Arc::clone(&outstanding_requests);
                move |observer| {
                    observer.observe_u64(
                        &outstanding_requests_gauge,
                        outstanding_requests.load(Ordering::Relaxed),
                        &[],
                    );
                    observer.observe_u64(
                        &max_outstanding_requests_gauge,
                        max_outstanding_requests,
                        &[],
                    );
                }
            },
        )?;

        let stacked_requests_gauge = meter
            .u64_observable_gauge(Self::metric_name(
                prefix,
                Self::STACKED_REQUESTS_METRIC_NAME,
            ))
            .with_description("Number of requests currently waiting in the LIFO queue.")
            .with_unit("{request}")
            .init();

        meter.register_callback(&[stacked_requests_gauge.as_any()], {
            let stacked_requests = Arc::clone(&stacked_requests);
            move |observer| {
                observer.observe_u64(
                    &stacked_requests_gauge,
                    stacked_requests.load(Ordering::Relaxed),
                    &[],
                );
            }
        })?;

        let wait_time_histogram = meter
            .f64_histogram(Self::metric_name(prefix, Self::WAIT_TIME_METRIC_NAME))
            .with_description("Time spent waiting by items in LIFO queue before being dequeued")
            .with_unit("s")
            .init();

        // Counters for different request lifecycle events
        let requests_processed_immediately = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_PROCESSED_IMMEDIATELY_METRIC_NAME,
            ))
            .with_description("Number of requests processed immediately without queueing")
            .with_unit("{request}")
            .init();

        let requests_queued = meter
            .u64_counter(Self::metric_name(prefix, Self::REQUESTS_QUEUED_METRIC_NAME))
            .with_description("Number of requests that were queued")
            .with_unit("{request}")
            .init();

        let requests_dequeued = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_DEQUEUED_METRIC_NAME,
            ))
            .with_description("Number of requests that were dequeued and started processing")
            .with_unit("{request}")
            .init();

        let requests_rejected = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_REJECTED_METRIC_NAME,
            ))
            .with_description("Number of requests rejected due to queue being full")
            .with_unit("{request}")
            .init();

        let requests_cancelled = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_CANCELLED_METRIC_NAME,
            ))
            .with_description("Number of requests that were cancelled")
            .with_unit("{request}")
            .init();

        let requests_timeout_queue = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_TIMEOUT_QUEUE_METRIC_NAME,
            ))
            .with_description("Number of requests that timed out while waiting in the queue")
            .with_unit("{request}")
            .init();

        Ok(Self {
            outstanding_requests,
            stacked_requests,
            wait_time_histogram,
            requests_processed_immediately,
            requests_queued,
            requests_dequeued,
            requests_rejected,
            requests_cancelled,
            requests_timeout_queue,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use backoff::{future::retry, ExponentialBackoff};
    use futures::{future::join_all, Future};
    use janus_aggregator_core::test_util::noop_meter;
    use janus_core::test_util::install_test_trace_subscriber;
    use opentelemetry_sdk::metrics::data::{Gauge, Sum};
    use quickcheck::{quickcheck, Arbitrary, TestResult};
    use tokio::{
        runtime::Builder as RuntimeBuilder,
        sync::Notify,
        task::{yield_now, JoinHandle},
        time::{sleep, timeout},
    };
    use tracing::debug;
    use trillium::{Conn, Handler, Status};
    use trillium_testing::{assert_ok, methods::get};

    use crate::{
        aggregator::queue::{queued_lifo, LIFORequestQueue, Metrics},
        metrics::test_util::InMemoryMetricsInfrastructure,
    };

    /// Some tests busy loop waiting for a condition to become true. Avoid hanging broken tests
    /// indefinitely by wrapping those tests in a timeout.
    const TEST_TIMEOUT: Duration = Duration::from_secs(15);

    async fn get_outstanding_requests_gauge(
        metrics: &InMemoryMetricsInfrastructure,
        meter_prefix: &str,
    ) -> Option<usize> {
        Some(
            metrics
                .collect()
                .await
                // The metric may not be immediately available when we need it, so return an Option
                // instead of unwrapping.
                .get(&Metrics::metric_name(
                    meter_prefix,
                    Metrics::OUTSTANDING_REQUESTS_METRIC_NAME,
                ))?
                .data
                .as_any()
                .downcast_ref::<Gauge<u64>>()
                .unwrap()
                .data_points[0]
                .value
                .try_into()
                .unwrap(),
        )
    }

    async fn wait_for(
        metrics: &InMemoryMetricsInfrastructure,
        meter_prefix: &str,
        condition: impl Fn(usize) -> bool,
    ) {
        while get_outstanding_requests_gauge(metrics, meter_prefix)
            .await
            .map(|metric| !condition(metric))
            .unwrap_or(true)
        {
            // Nominal sleep to prevent this loop from being too tight.
            sleep(Duration::from_millis(3)).await;
        }
    }

    struct HangingHandler {
        unhang: Arc<Notify>,
    }

    #[async_trait]
    impl Handler for HangingHandler {
        async fn run(&self, conn: trillium::Conn) -> trillium::Conn {
            let _ = self.unhang.notified().await;
            conn.ok("hello")
        }
    }

    async fn fill_queue(
        handler: Arc<impl Handler>,
        concurrency: u32,
        depth: usize,
        metrics: &InMemoryMetricsInfrastructure,
        meter_prefix: &str,
    ) -> Vec<JoinHandle<()>> {
        debug!("filling queue");

        let mut requests = Vec::new();

        let backoff = ExponentialBackoff {
            initial_interval: Duration::from_nanos(1),
            max_interval: Duration::from_nanos(30),
            multiplier: 2.0,
            ..Default::default()
        };

        debug!("spawning requests");
        for _ in 0..(concurrency as usize + depth) {
            let handler = Arc::clone(&handler);
            let backoff = backoff.clone();
            requests.push(tokio::spawn({
                async move {
                    retry(backoff, || {
                        let handler = Arc::clone(&handler);
                        async move {
                            let request = get("/").run_async(&handler).await;
                            match request.status().unwrap() {
                                Status::Ok => Ok(()),
                                Status::RequestTimeout => Ok(()), // Timeouts are fine during filling
                                Status::TooManyRequests => {
                                    Err(backoff::Error::transient(format!("429, retry")))
                                }
                                status => Err(backoff::Error::Permanent(format!(
                                    "Unexpected status: {status:?}"
                                ))),
                            }
                        }
                    })
                    .await
                    .unwrap();
                }
            }));
        }

        debug!("waiting for queue to be full");
        wait_for(metrics, meter_prefix, |q| q == concurrency as usize + depth).await;

        requests
    }

    #[derive(Debug, Clone, Copy)]
    struct Parameters {
        /// Some deadlock behavior depends on whether we're multi or single threaded.
        runtime_flavor: RuntimeFlavor,
        depth: usize,
        concurrency: u32,
        requests: usize,
        /// Request timeout in milliseconds. None means no timeout. Only used in the _full test.
        request_timeout_ms: Option<u64>,
    }

    impl Arbitrary for Parameters {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                runtime_flavor: if bool::arbitrary(g) {
                    RuntimeFlavor::CurrentThread
                } else {
                    RuntimeFlavor::MultiThread
                },
                depth: u8::arbitrary(g) as usize,
                concurrency: u8::arbitrary(g) as u32 + 1,
                requests: (u16::arbitrary(g) / 10) as usize + 1,
                request_timeout_ms: if bool::arbitrary(g) {
                    // Between 10 and 2000ms
                    Some(10u64 + u64::arbitrary(g) % 1990)
                } else {
                    None
                },
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum RuntimeFlavor {
        CurrentThread,
        MultiThread,
    }

    impl RuntimeFlavor {
        fn run<F: Future>(&self, future: F) -> F::Output {
            match self {
                RuntimeFlavor::CurrentThread => RuntimeBuilder::new_current_thread(),
                RuntimeFlavor::MultiThread => RuntimeBuilder::new_multi_thread(),
            }
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move { timeout(TEST_TIMEOUT, future).await.unwrap() })
        }
    }

    #[test]
    fn quickcheck_lifo_concurrency() {
        struct ConcurrencyAssertingHandler {
            max_concurrency: u32,
            concurrency: AtomicU32,
        }

        #[async_trait]
        impl Handler for ConcurrencyAssertingHandler {
            async fn run(&self, conn: trillium::Conn) -> trillium::Conn {
                let concurrency = self.concurrency.fetch_add(1, Ordering::Relaxed);
                assert!(concurrency < self.max_concurrency);

                // Somewhat arbitrary yield point, to give the dispatcher a chance to signal
                // another concurring future. This is mostly pertinent if we're running the test on
                // a current_thread runtime. Otherwise, without await points, on a current_thread
                // runtime, this function won't yield.
                yield_now().await;

                let conn = conn.ok("hello");
                self.concurrency.fetch_sub(1, Ordering::Relaxed);
                conn
            }
        }

        fn qc(parameters: Parameters) {
            debug!(?parameters, "quickcheck_lifo_concurrency parameters");
            let Parameters {
                runtime_flavor,
                depth,
                concurrency,
                requests,
                request_timeout_ms,
            } = parameters;

            runtime_flavor.run(async move {
                let meter_prefix = "test";
                let request_timeout = request_timeout_ms.map(Duration::from_millis);
                let queue = Arc::new(
                    LIFORequestQueue::new(
                        concurrency,
                        depth,
                        &noop_meter(),
                        meter_prefix,
                        request_timeout,
                    )
                    .unwrap(),
                );
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    ConcurrencyAssertingHandler {
                        concurrency: Default::default(),
                        max_concurrency: concurrency,
                    },
                ));

                join_all((0..requests).map(|_| {
                    let handler = Arc::clone(&handler);
                    async move {
                        get("/").run_async(&handler).await;
                    }
                }))
                .await;
            });
        }

        install_test_trace_subscriber();
        quickcheck(qc as fn(Parameters));
    }

    #[test]
    fn quickcheck_lifo_cancel() {
        fn qc(parameters: Parameters) {
            debug!(?parameters, "quickcheck_lifo_cancel parameters");
            let Parameters {
                runtime_flavor,
                depth,
                concurrency,
                ..
            } = parameters;

            runtime_flavor.run(async move {
                let meter_prefix = "test";
                let metrics = InMemoryMetricsInfrastructure::new();
                let unhang = Arc::new(Notify::new());
                let queue = Arc::new(
                    LIFORequestQueue::new(concurrency, depth, &metrics.meter, meter_prefix, None)
                        .unwrap(),
                );
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    HangingHandler {
                        unhang: Arc::clone(&unhang),
                    },
                ));

                let requests = fill_queue(
                    Arc::clone(&handler),
                    concurrency,
                    depth,
                    &metrics,
                    meter_prefix,
                )
                .await;

                let concurrency = concurrency as usize;
                debug!("freeing up one slot in the queue");
                unhang.notify_one();
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth - 1).await;

                debug!("sending new request, should be queued");
                let request_handler = Arc::clone(&handler);
                let request =
                    tokio::spawn(async move { get("/").run_async(&request_handler).await });

                debug!("waiting for new request to be queued");
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth).await;

                debug!("cancelling request");
                request.abort();

                debug!("waiting for new request to be cancelled");
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth - 1).await;

                debug!("cancelling outstanding requests");
                requests.iter().for_each(|request| request.abort());

                debug!("waiting for requests to be cancelled");
                wait_for(&metrics, meter_prefix, |q| q == 0).await;

                debug!("sending new request");
                unhang.notify_one();
                let request = get("/").run_async(&handler).await;
                assert_ok!(request);

                debug!("waiting for futures to terminate");
                for handle in requests {
                    // These handles will return a JoinError, but we're moreso interested to see if
                    // they've all terminated.
                    let _ = handle.await;
                }

                debug!("shutting down metrics");
                metrics.shutdown().await;
            });
        }

        install_test_trace_subscriber();
        quickcheck(qc as fn(Parameters));
    }

    #[test]
    fn quickcheck_lifo_full() {
        fn qc(parameters: Parameters) {
            debug!(?parameters, "quickcheck_lifo_full parameters");
            let Parameters {
                runtime_flavor,
                depth,
                concurrency,
                request_timeout_ms,
                ..
            } = parameters;

            runtime_flavor.run(async move {
                let unhang = Arc::new(Notify::new());
                let meter_prefix = "test";
                let metrics = InMemoryMetricsInfrastructure::new();
                let request_timeout = request_timeout_ms.map(Duration::from_millis);
                let queue = Arc::new(
                    LIFORequestQueue::new(
                        concurrency,
                        depth,
                        &metrics.meter,
                        meter_prefix,
                        request_timeout,
                    )
                    .unwrap(),
                );
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    HangingHandler {
                        unhang: Arc::clone(&unhang),
                    },
                ));

                let requests = fill_queue(
                    Arc::clone(&handler),
                    concurrency,
                    depth,
                    &metrics,
                    meter_prefix,
                )
                .await;

                debug!("sending request, should fail");
                let request = get("/").run_async(&handler).await;
                assert_matches!(
                    request.status(),
                    Some(Status::TooManyRequests) | Some(Status::RequestTimeout)
                );

                debug!("draining the queue");
                while get_outstanding_requests_gauge(&metrics, meter_prefix).await > Some(0) {
                    unhang.notify_one();
                }
                for handle in requests {
                    handle.await.unwrap();
                }

                debug!("sending request, should succeed");
                unhang.notify_one();
                let request = get("/").run_async(&handler).await;
                assert_ok!(request);

                debug!("shutting down metrics");
                metrics.shutdown().await;
            });
        }

        install_test_trace_subscriber();
        quickcheck(qc as fn(Parameters));
    }

    #[test]
    fn quickcheck_lifo() {
        fn qc(parameters: Parameters) -> TestResult {
            debug!(?parameters, "quickcheck_lifo parameters");
            let Parameters {
                runtime_flavor,
                depth,
                concurrency,
                ..
            } = parameters;

            if depth == 0 {
                return TestResult::discard();
            }

            runtime_flavor.run(async move {
                let unhang = Arc::new(Notify::new());
                let meter_prefix = "test";
                let metrics = InMemoryMetricsInfrastructure::new();
                let queue = Arc::new(
                    LIFORequestQueue::new(
                        concurrency,
                        depth,
                        &metrics.meter,
                        meter_prefix,
                        None, // Disable timeouts for the core test
                    )
                    .unwrap(),
                );
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    HangingHandler {
                        unhang: Arc::clone(&unhang),
                    },
                ));

                let requests = fill_queue(
                    Arc::clone(&handler),
                    concurrency,
                    depth,
                    &metrics,
                    meter_prefix,
                )
                .await;

                let concurrency = concurrency as usize;
                debug!("freeing up one slot in the queue");
                unhang.notify_one();
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth - 1).await;

                debug!("sending new request, should be queued");
                let request_queue = Arc::clone(&queue);
                let request = tokio::spawn(async move {
                    get("/")
                        .run_async(&queued_lifo(request_queue, |conn: Conn| async move {
                            conn.ok("hello")
                        }))
                        .await
                });

                debug!("waiting for new request to be queued");
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth).await;

                debug!("allowing one random request to proceed");
                unhang.notify_one();

                debug!("new request should be immediately processed");
                let request = request.await.unwrap();
                assert_ok!(request);

                debug!("draining the queue");
                while get_outstanding_requests_gauge(&metrics, meter_prefix).await > Some(0) {
                    unhang.notify_one();
                }

                debug!("waiting for futures to terminate");
                for handle in requests {
                    handle.await.unwrap();
                }

                debug!("shutting down metrics");
                metrics.shutdown().await;

                TestResult::passed()
            })
        }

        install_test_trace_subscriber();
        quickcheck(qc as fn(Parameters) -> TestResult);
    }

    #[test]
    fn test_request_timeout() {
        install_test_trace_subscriber();

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let meter_prefix = "test";
            let metrics = InMemoryMetricsInfrastructure::new();
            let concurrency = 1;
            let depth = 1;
            let timeout = Duration::from_millis(100);

            let queue = Arc::new(
                LIFORequestQueue::new(
                    concurrency,
                    depth,
                    &metrics.meter,
                    meter_prefix,
                    Some(timeout),
                )
                .unwrap(),
            );

            // Create a hanging handler that never releases requests
            let unhang = Arc::new(Notify::new());
            let handler = Arc::new(queued_lifo(
                Arc::clone(&queue),
                HangingHandler {
                    unhang: Arc::clone(&unhang),
                },
            ));

            // Fill up the active slots (concurrency) but leave queue empty
            let mut requests = Vec::new();
            for _ in 0..concurrency {
                let handler = Arc::clone(&handler);
                requests.push(tokio::spawn(
                    async move { get("/").run_async(&handler).await },
                ));
            }

            // Wait for all active slots to be filled
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Now make a request that will be queued and should timeout
            let start = Instant::now();
            let result = get("/").run_async(&handler).await;
            let elapsed = start.elapsed();

            // Should have timed out with RequestTimeout status
            assert_eq!(
                result.status().unwrap(),
                Status::RequestTimeout,
                "Expected RequestTimeout (408) but got {:?}",
                result.status().unwrap()
            );
            // Should have taken approximately the timeout duration (with some tolerance)
            assert!(
                elapsed >= timeout && elapsed < timeout + Duration::from_millis(200),
                "Request took {elapsed:?}, expected around {timeout:?}"
            );

            // Check timeout metric was incremented
            let timeout_count = metrics
                .collect()
                .await
                .get(&Metrics::metric_name(
                    meter_prefix,
                    Metrics::REQUESTS_TIMEOUT_QUEUE_METRIC_NAME,
                ))
                .unwrap()
                .data
                .as_any()
                .downcast_ref::<Sum<u64>>()
                .unwrap()
                .data_points[0]
                .value;
            assert_eq!(timeout_count, 1);

            // Clean up: cancel the hanging requests
            for request in requests {
                request.abort();
            }

            metrics.shutdown().await;
        });
    }
}
