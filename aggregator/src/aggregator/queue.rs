use itertools::Itertools;
use janus_aggregator_core::TIME_HISTOGRAM_BOUNDARIES;
use janus_core::time::{InstantClock, InstantLike, RealInstantClock};
use opentelemetry::{
    KeyValue,
    metrics::{Histogram, Meter},
};
use opentelemetry_sdk::metrics::MetricError;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    select,
    sync::{
        OwnedSemaphorePermit, Semaphore, mpsc,
        oneshot::{self},
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
pub struct LIFORequestQueue<C: InstantClock = RealInstantClock> {
    /// Sends messages to the dispatcher task.
    dispatcher_tx: mpsc::UnboundedSender<DispatcherMessage>,

    /// Used to generate unique request IDs for identifying requests in the queue. Request numbers
    /// are unique as long as this counter doesn't overflow, which shouldn't happen under practical
    /// usage. For instance, it takes approximately 584,000 years at 1M QPS to overflow a 64-bit
    /// counter.
    id_counter: AtomicU64,

    metrics: Metrics<C>,

    instant_clock: C,
}

impl LIFORequestQueue {
    /// Creates a new [`Self`] with the real clock.
    ///
    /// `concurrency` must be greater than zero.
    ///
    /// `meter_prefix` is a string to disambiguate one queue from another in the metrics, while
    /// using the same meter. All metric names will be prefixed with this string.
    pub fn new(
        concurrency: u32,
        depth: usize,
        meter: &Meter,
        meter_prefix: &str,
    ) -> Result<Self, Error> {
        Self::with_instant_clock(concurrency, depth, meter, meter_prefix, RealInstantClock)
    }
}

impl<C: InstantClock> LIFORequestQueue<C> {
    /// Creates a new [`Self`] with a custom instant clock.
    ///
    /// `concurrency` must be greater than zero.
    ///
    /// `meter_prefix` is a string to disambiguate one queue from another in the metrics, while
    /// using the same meter. All metric names will be prefixed with this string.
    pub fn with_instant_clock(
        concurrency: u32,
        depth: usize,
        meter: &Meter,
        meter_prefix: &str,
        instant_clock: C,
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
            .map_err(|e| Error::Internal(e.into()))?;
        Self::dispatcher(message_rx, concurrency, depth, metrics.clone());

        Ok(Self {
            id_counter,
            dispatcher_tx: message_tx,
            metrics,
            instant_clock,
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
        metrics: Metrics<C>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Use a BTreeMap to allow for cancellation (i.e. removal) of waiting requests in
            // sublinear time.
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
                                            permit_tx.send(Ok(permit))
                                        } else if stack.len() < depth {
                                            let result = stack.insert(id, permit_tx);
                                            if result.is_some() {
                                                // Avoid panicking on this bug, since if this
                                                // process dies, request processing stops.
                                                error!(?id, "bug: overwrote existing request in the queue");
                                            }
                                        } else {
                                            permit_tx.send(Err(Error::TooManyRequests));
                                        }
                                    },
                                    DispatcherMessage::Cancel(id) => {
                                        debug!(?id, "removing from the queue");
                                        stack.remove(&id);
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
                            Some((_, permit_tx)) => permit_tx.send(Ok(permit)),
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
            }
        })
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, Error> {
        let id = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let (permit_tx, permit_rx) = oneshot::channel();

        let enqueue_time = self.instant_clock.now();
        self.dispatcher_tx
            .send(DispatcherMessage::Enqueue(id, PermitTx(permit_tx)))
            // We don't necessarily panic because the dispatcher task could be shutdown as part of
            // process shutdown, while a request is in flight.
            .map_err(|_| Error::Internal("dispatcher task died".into()))?;

        /// Sends a cancellation message over the given channel when the guard is dropped, unless
        /// [`Self::disarm`] is called.
        struct CancelDropGuard<C: InstantClock, I: InstantLike> {
            id: u64,
            sender: mpsc::UnboundedSender<DispatcherMessage>,
            armed: bool,
            metrics: Metrics<C>,
            enqueue_time: I,
        }

        impl<C: InstantClock, I: InstantLike> CancelDropGuard<C, I> {
            fn new(
                id: u64,
                sender: mpsc::UnboundedSender<DispatcherMessage>,
                metrics: Metrics<C>,
                enqueue_time: I,
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

        impl<C: InstantClock, I: InstantLike> Drop for CancelDropGuard<C, I> {
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

        let mut drop_guard = CancelDropGuard::<C, _>::new(
            id,
            self.dispatcher_tx.clone(),
            self.metrics.clone(),
            enqueue_time.clone(),
        );
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
        permit.map_err(|_| Error::Internal("rx channel dropped".into()))?
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
pub struct LIFOQueueHandler<H, C: InstantClock = RealInstantClock> {
    #[handler(except = [run])]
    handler: H,
    queue: Arc<LIFORequestQueue<C>>,
}

impl<H: Handler, C: InstantClock> LIFOQueueHandler<H, C> {
    pub fn new(queue: Arc<LIFORequestQueue<C>>, handler: H) -> Self {
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
pub fn queued_lifo<H: Handler, C: InstantClock>(
    queue: Arc<LIFORequestQueue<C>>,
    handler: H,
) -> LIFOQueueHandler<H, C> {
    LIFOQueueHandler::new(queue, handler)
}

#[derive(Clone, Debug)]
struct Metrics<C: InstantClock> {
    /// The approximate number of requests currently being serviced by the queue. It's approximate
    /// since the queue length may have changed before the measurement is taken. In practice, the
    /// error should only be +/- 1. It is also more or less suitable for synchronization during
    /// tests.
    outstanding_requests: Arc<AtomicU64>,

    /// Histogram measuring how long a queue item waited before being dequeued.
    wait_time_histogram: Histogram<f64>,

    _phantom: std::marker::PhantomData<C>,
}

impl<C: InstantClock> Metrics<C> {
    const OUTSTANDING_REQUESTS_METRIC_NAME: &'static str = "outstanding_requests";
    const MAX_OUTSTANDING_REQUESTS_METRIC_NAME: &'static str = "max_outstanding_requests";
    const WAIT_TIME_METRIC_NAME: &'static str = "lifo_queue_wait_time";

    fn metric_name(prefix: &str, name: &str) -> String {
        [prefix, name].into_iter().join("_")
    }

    fn new(
        meter: &Meter,
        prefix: &str,
        max_outstanding_requests: u64,
    ) -> Result<Self, MetricError> {
        let outstanding_requests = Arc::new(AtomicU64::new(0));
        let _outstanding_requests_gauge = meter
            .u64_observable_gauge(Self::metric_name(
                prefix,
                Self::OUTSTANDING_REQUESTS_METRIC_NAME,
            ))
            .with_description(
                "The approximate number of requests currently being serviced by the aggregator.",
            )
            .with_unit("{request}")
            .with_callback({
                let outstanding_requests = Arc::clone(&outstanding_requests);
                move |observer| observer.observe(outstanding_requests.load(Ordering::Relaxed), &[])
            })
            .build();
        let _max_outstanding_requests_gauge = meter
            .u64_observable_gauge(Self::metric_name(
                prefix,
                Self::MAX_OUTSTANDING_REQUESTS_METRIC_NAME,
            ))
            .with_description(
                "The maximum number of requests that the aggregator can service at a time.",
            )
            .with_unit("{request}")
            .with_callback(move |observer| observer.observe(max_outstanding_requests, &[]))
            .build();

        let wait_time_histogram = meter
            .f64_histogram(Self::metric_name(prefix, Self::WAIT_TIME_METRIC_NAME))
            .with_boundaries(TIME_HISTOGRAM_BOUNDARIES.to_vec())
            .with_description("Time spent waiting by items in LIFO queue before being dequeued")
            .with_unit("s")
            .build();

        Ok(Self {
            outstanding_requests,
            wait_time_histogram,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
    use futures::{Future, future::join_all};
    use janus_aggregator_core::test_util::noop_meter;
    use janus_core::{
        test_util::install_test_trace_subscriber,
        time::{MockInstantClock, RealInstantClock},
    };
    use opentelemetry_sdk::metrics::data::Gauge;
    use quickcheck::{Arbitrary, TestResult, quickcheck};
    use tokio::{
        runtime::Builder as RuntimeBuilder,
        sync::Notify,
        task::{JoinHandle, yield_now},
        time::timeout,
    };
    use tracing::debug;
    use trillium::{Conn, Handler, Status};
    use trillium_testing::{assert_ok, assert_status, methods::get};

    use super::Error;

    use crate::{
        aggregator::queue::{LIFORequestQueue, Metrics, queued_lifo},
        metrics::test_util::InMemoryMetricInfrastructure,
    };

    /// Some tests busy loop waiting for a condition to become true. Avoid hanging broken tests
    /// indefinitely by wrapping those tests in a timeout.
    const TEST_TIMEOUT: Duration = Duration::from_secs(15);

    async fn get_outstanding_requests_gauge(
        metrics: &InMemoryMetricInfrastructure,
        meter_prefix: &str,
    ) -> Option<usize> {
        Some(
            metrics
                .collect()
                .await
                // The metric may not be immediately available when we need it, so return an Option
                // instead of unwrapping.
                .get(&Metrics::<RealInstantClock>::metric_name(
                    meter_prefix,
                    Metrics::<RealInstantClock>::OUTSTANDING_REQUESTS_METRIC_NAME,
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
        metrics: &InMemoryMetricInfrastructure,
        meter_prefix: &str,
        condition: impl Fn(usize) -> bool,
    ) {
        while get_outstanding_requests_gauge(metrics, meter_prefix)
            .await
            .map(|metric| !condition(metric))
            .unwrap_or(true)
        {
            // Yield to allow other tasks to run
            yield_now().await;
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
        metrics: &InMemoryMetricInfrastructure,
        meter_prefix: &str,
    ) -> Vec<JoinHandle<()>> {
        debug!("filling queue");

        let mut requests = Vec::new();

        let backoff = ExponentialBuilder::new()
            .with_min_delay(Duration::from_nanos(1))
            .with_factor(2.0)
            .with_max_times(30);

        debug!("spawning requests");
        for _ in 0..(concurrency as usize + depth) {
            let handler = Arc::clone(&handler);
            let backoff = backoff.build();
            requests.push(tokio::spawn({
                async move {
                    (|| async {
                        let handler = Arc::clone(&handler);
                        let request = get("/").run_async(&handler).await;
                        if request.status().unwrap() == Status::Ok {
                            Ok(())
                        } else {
                            Err(Error::Internal("Test error".into()))
                        }
                    })
                    .retry(backoff)
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
            } = parameters;

            runtime_flavor.run(async move {
                let meter_prefix = "test";
                let queue = Arc::new(
                    LIFORequestQueue::new(concurrency, depth, &noop_meter(), meter_prefix).unwrap(),
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
                let metrics = InMemoryMetricInfrastructure::new();
                let unhang = Arc::new(Notify::new());
                let instant_clock = MockInstantClock::new();
                let queue = Arc::new(
                    LIFORequestQueue::with_instant_clock(
                        concurrency,
                        depth,
                        &metrics.meter,
                        meter_prefix,
                        instant_clock,
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
                ..
            } = parameters;

            runtime_flavor.run(async move {
                let unhang = Arc::new(Notify::new());
                let meter_prefix = "test";
                let metrics = InMemoryMetricInfrastructure::new();
                let instant_clock = MockInstantClock::new();
                let queue = Arc::new(
                    LIFORequestQueue::with_instant_clock(
                        concurrency,
                        depth,
                        &metrics.meter,
                        meter_prefix,
                        instant_clock,
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
                assert_status!(request, Status::TooManyRequests);

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
                let metrics = InMemoryMetricInfrastructure::new();
                let instant_clock = MockInstantClock::new();
                let queue = Arc::new(
                    LIFORequestQueue::with_instant_clock(
                        concurrency,
                        depth,
                        &metrics.meter,
                        meter_prefix,
                        instant_clock,
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
}
