use std::{
    collections::BTreeMap,
    mem::forget,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use itertools::Itertools;
use opentelemetry::metrics::{Gauge, Meter};
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
}

impl LIFORequestQueue {
    /// Creates a new [`Self`].
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
        if concurrency < 1 {
            return Err(Error::InvalidConfiguration(
                "concurrency must be greater than 0",
            ));
        }

        let (message_tx, message_rx) = mpsc::unbounded_channel();
        let id_counter = Default::default();
        let metrics = Metrics::new(meter, meter_prefix);
        Self::dispatcher(message_rx, concurrency, depth, metrics);

        Ok(Self {
            id_counter,
            dispatcher_tx: message_tx,
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
                metrics.outstanding_requests.record(
                    (stack.len() + usize::try_from(concurrency).unwrap() - permits.num_permits())
                        .try_into()
                        .unwrap(),
                    &[],
                );
            }
        })
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, Error> {
        let id = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let (permit_tx, permit_rx) = oneshot::channel();

        self.dispatcher_tx
            .send(DispatcherMessage::Enqueue(id, PermitTx(permit_tx)))
            // We don't necessarily panic because the dispatcher task could be shutdown as part of
            // process shutdown, while a request is in flight.
            .map_err(|_| Error::Internal("dispatcher task died".to_string()))?;

        /// Sends a cancellation message over the given channel when the guard is dropped, unless
        /// it's forgotten with [`forget`].
        struct CancelDropGuard(u64, mpsc::UnboundedSender<DispatcherMessage>);

        impl Drop for CancelDropGuard {
            fn drop(&mut self) {
                let _ = self
                    .1
                    .send(DispatcherMessage::Cancel(self.0))
                    .map_err(|err| warn!("failed to send cancellation message: {:?}", err));
            }
        }

        let drop_guard = CancelDropGuard(id, self.dispatcher_tx.clone());
        let permit = permit_rx.await;
        forget(drop_guard);

        // If the rx channel is prematurely dropped, we'll reach this error, indicating that
        // something has gone wrong with the dispatcher task or it has shutdown. If the drop guard
        // causes the rx channel to be dropped, we shouldn't reach this error because the overall
        // future would have been dropped.
        permit.map_err(|_| Error::Internal("rx channel dropped".to_string()))?
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

type PermitRx = oneshot::Receiver<Result<OwnedSemaphorePermit, Error>>;

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

struct Metrics {
    /// The approximate number of requests currently being serviced by the queue. It's approximate
    /// since the queue length may have changed before the measurement is taken. In practice, the
    /// error should only be +/- 1. It is also more or less suitable for synchronization during
    /// tests.
    outstanding_requests: Gauge<u64>,
}

impl Metrics {
    const OUTSTANDING_REQUESTS_METRIC_NAME: &'static str = "outstanding_requests";

    fn new(meter: &Meter, prefix: &str) -> Self {
        Self {
            outstanding_requests: meter
                .u64_gauge(Self::get_outstanding_requests_name(prefix))
                .with_description(concat!(
                    "The approximate number of requests currently being serviced by the ",
                    "aggregator."
                ))
                .with_unit("{request}")
                .init(),
        }
    }

    fn get_outstanding_requests_name(prefix: &str) -> String {
        [prefix, Self::OUTSTANDING_REQUESTS_METRIC_NAME]
            .into_iter()
            .join("_")
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use backoff::{future::retry, ExponentialBackoff};
    use futures::{future::join_all, Future};
    use janus_aggregator_core::test_util::noop_meter;
    use janus_core::test_util::install_test_trace_subscriber;
    use opentelemetry_sdk::metrics::data::Gauge;
    use quickcheck::{quickcheck, Arbitrary, TestResult};
    use tokio::{
        runtime::Builder as RuntimeBuilder,
        sync::Notify,
        task::{yield_now, JoinHandle},
        time::{sleep, timeout},
    };
    use tracing::debug;
    use trillium::{Conn, Handler, Status};
    use trillium_testing::{assert_ok, assert_status, methods::get};

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
                .get(&Metrics::get_outstanding_requests_name(meter_prefix))?
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
        loop {
            let metric = get_outstanding_requests_gauge(&metrics, meter_prefix).await;
            if let Some(metric) = metric {
                if condition(metric) {
                    return;
                }
            }
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
                            if request.status().unwrap() == Status::Ok {
                                Ok(())
                            } else {
                                Err(backoff::Error::transient(()))
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
                let metrics = InMemoryMetricsInfrastructure::new();
                let unhang = Arc::new(Notify::new());
                let queue = Arc::new(
                    LIFORequestQueue::new(concurrency, depth, &metrics.meter, meter_prefix)
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
                let metrics = InMemoryMetricsInfrastructure::new();
                let queue = Arc::new(
                    LIFORequestQueue::new(concurrency, depth, &metrics.meter, meter_prefix)
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
                assert_status!(request, Status::ServiceUnavailable);

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
                    LIFORequestQueue::new(concurrency, depth, &metrics.meter, meter_prefix)
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
