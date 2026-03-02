use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use itertools::Itertools;
use janus_aggregator_core::TIME_HISTOGRAM_BOUNDARIES;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Histogram, Meter},
};
use opentelemetry_sdk::metrics::MetricError;
use tokio::{
    select,
    sync::{
        OwnedSemaphorePermit, Semaphore, mpsc,
        oneshot::{self},
    },
    task::JoinHandle,
};
use tracing::{debug, error, warn};

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
            .map_err(|e| Error::Internal(e.into()))?;
        Self::dispatcher(message_rx, concurrency, depth, metrics.clone());

        Ok(Self {
            id_counter,
            dispatcher_tx: message_tx,
            request_timeout,
            metrics,
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
                                        stack.remove(&id);
                                        metrics.requests_cancelled.add(1, &[]);
                                    },
                                }
                            }
                            // The receiver is held open for at least the life of the
                            // LIFORequestQueue by the stored dispatcher_rx. If that's been dropped,
                            // and all other message senders have been dropped (one each is cloned
                            // to requests for cancellation), then the dispatcher can be closed.
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

                let stack_len = stack.len();
                // Unwrap safety: only fails on architectures where usize is less than 32 bits, or
                // greater than 64 bits.
                metrics.outstanding_requests.store(
                    (stack_len + usize::try_from(concurrency).unwrap() - permits.num_permits())
                        .try_into()
                        .unwrap(),
                    Ordering::Relaxed,
                );
                metrics
                    .stacked_requests
                    .store(u64::try_from(stack_len).unwrap(), Ordering::Relaxed);
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
            .map_err(|_| Error::Internal("dispatcher task died".into()))?;

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

            // If the rx channel is prematurely dropped, we'll reach this error, indicating
            // that something has gone wrong with the dispatcher task or it has shutdown. If
            // the drop guard causes the rx channel to be dropped, we shouldn't reach this
            // error because the overall future would have been dropped.
            permit.map_err(|_| {
                Error::Internal("permit channel dropped; dispatcher may have shut down?".into())
            })?
        };

        // If a request timeout is provided, impose it.
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

/// Axum middleware that queues requests through a [`LIFORequestQueue`].
///
/// This acquires a permit from the queue before forwarding the request to the next handler.
/// If the queue is full, returns a TooManyRequests error. If the request times out waiting
/// in the queue, returns a RequestTimeout error.
pub async fn lifo_queue_middleware(
    axum::extract::State(queue): axum::extract::State<Arc<LIFORequestQueue>>,
    request: Request,
    next: Next,
) -> Response {
    match queue.acquire().await {
        Ok(_permit) => next.run(request).await,
        Err(err) => err.into_response(),
    }
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
    ) -> Result<Self, MetricError> {
        let outstanding_requests = Arc::new(AtomicU64::new(0));
        let stacked_requests = Arc::new(AtomicU64::new(0));

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
        let _stacked_requests_gauge = meter
            .u64_observable_gauge(Self::metric_name(
                prefix,
                Self::STACKED_REQUESTS_METRIC_NAME,
            ))
            .with_description("Number of requests currently waiting in the LIFO queue.")
            .with_unit("{request}")
            .with_callback({
                let stacked_requests = Arc::clone(&stacked_requests);
                move |observer| observer.observe(stacked_requests.load(Ordering::Relaxed), &[])
            })
            .build();

        let wait_time_histogram = meter
            .f64_histogram(Self::metric_name(prefix, Self::WAIT_TIME_METRIC_NAME))
            .with_boundaries(TIME_HISTOGRAM_BOUNDARIES.to_vec())
            .with_description("Time spent waiting by items in LIFO queue before being dequeued")
            .with_unit("s")
            .build();

        // Counters for different request lifecycle events
        let requests_processed_immediately = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_PROCESSED_IMMEDIATELY_METRIC_NAME,
            ))
            .with_description("Number of requests processed immediately without queueing")
            .with_unit("{request}")
            .build();

        let requests_queued = meter
            .u64_counter(Self::metric_name(prefix, Self::REQUESTS_QUEUED_METRIC_NAME))
            .with_description("Number of requests that were queued")
            .with_unit("{request}")
            .build();

        let requests_rejected = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_REJECTED_METRIC_NAME,
            ))
            .with_description("Number of requests rejected due to queue being full")
            .with_unit("{request}")
            .build();

        let requests_cancelled = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_CANCELLED_METRIC_NAME,
            ))
            .with_description("Number of requests that were cancelled")
            .with_unit("{request}")
            .build();

        let requests_timeout_queue = meter
            .u64_counter(Self::metric_name(
                prefix,
                Self::REQUESTS_TIMEOUT_QUEUE_METRIC_NAME,
            ))
            .with_description("Number of requests that timed out while waiting in the queue")
            .with_unit("{request}")
            .build();

        Ok(Self {
            outstanding_requests,
            stacked_requests,
            wait_time_histogram,
            requests_processed_immediately,
            requests_queued,
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
            Arc,
            atomic::{AtomicU32, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use axum::{
        Router, body::Body, extract::State, response::IntoResponse, routing::get as get_route,
    };
    use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
    use futures::{Future, future::join_all};
    use http::{Request, StatusCode};
    use janus_aggregator_core::test_util::noop_meter;
    use janus_core::test_util::install_test_trace_subscriber;
    use opentelemetry_sdk::metrics::data::{Gauge, Sum};
    use quickcheck::{Arbitrary, TestResult, quickcheck};
    use tokio::{
        runtime::Builder as RuntimeBuilder,
        sync::Notify,
        task::{JoinHandle, yield_now},
        time::{sleep, timeout},
    };
    use tower::ServiceExt;
    use tracing::debug;

    use super::{Error, LIFORequestQueue, Metrics, lifo_queue_middleware};
    use crate::metrics::test_util::InMemoryMetricInfrastructure;

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
        metrics: &InMemoryMetricInfrastructure,
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

    /// Build an axum router that uses the LIFO queue and a handler that blocks until notified.
    fn hanging_router(queue: Arc<LIFORequestQueue>, unhang: Arc<Notify>) -> Router {
        Router::new()
            .route(
                "/",
                get_route(move |State(unhang): State<Arc<Notify>>| async move {
                    unhang.notified().await;
                    StatusCode::OK
                }),
            )
            .with_state(unhang)
            .layer(axum::middleware::from_fn_with_state(
                queue,
                lifo_queue_middleware,
            ))
    }

    /// Send a GET / request through a router.
    async fn send_request(router: &Router) -> http::Response<Body> {
        router
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn fill_queue(
        router: &Router,
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
            let router = router.clone();
            let backoff = backoff.build();
            requests.push(tokio::spawn({
                async move {
                    (|| async {
                        let response = send_request(&router).await;
                        match response.status() {
                            StatusCode::OK => Ok(()),
                            StatusCode::TOO_MANY_REQUESTS => Ok(()),
                            status => Err(Error::Internal(
                                format!("Unexpected status: {status}").into(),
                            )),
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
                    // Between 50ms and 2000ms
                    Some(50u64 + u64::arbitrary(g) % 1950)
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
        fn run<F>(&self, future: F) -> F::Output
        where
            F: Future + Send + 'static,
            F::Output: Send,
        {
            let flavor = *self;
            let (sender, receiver) = mpsc::channel();
            let join_handle = thread::spawn(move || {
                let runtime = match flavor {
                    RuntimeFlavor::CurrentThread => RuntimeBuilder::new_current_thread(),
                    RuntimeFlavor::MultiThread => RuntimeBuilder::new_multi_thread(),
                }
                .enable_all()
                .build()
                .unwrap();
                let output =
                    runtime.block_on(async move { timeout(TEST_TIMEOUT, future).await.unwrap() });
                drop(runtime);
                sender.send(()).unwrap();
                output
            });
            receiver
                .recv_timeout(TEST_TIMEOUT * 2)
                .expect("timed out waiting for runtime thread");
            join_handle.join().unwrap()
        }
    }

    #[test]
    fn quickcheck_lifo_concurrency() {
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
                let concurrency_counter = Arc::new(AtomicU32::new(0));
                let max_concurrency = concurrency;
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

                let counter = concurrency_counter.clone();
                let router = Router::new()
                    .route(
                        "/",
                        get_route(move || {
                            let counter = counter.clone();
                            async move {
                                let c = counter.fetch_add(1, Ordering::Relaxed);
                                assert!(c < max_concurrency);
                                yield_now().await;
                                counter.fetch_sub(1, Ordering::Relaxed);
                                StatusCode::OK
                            }
                        }),
                    )
                    .layer(axum::middleware::from_fn_with_state(
                        queue,
                        lifo_queue_middleware,
                    ));

                join_all((0..requests).map(|_| {
                    let router = router.clone();
                    async move {
                        send_request(&router).await;
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
                let queue = Arc::new(
                    LIFORequestQueue::new(concurrency, depth, &metrics.meter, meter_prefix, None)
                        .unwrap(),
                );
                let router = hanging_router(Arc::clone(&queue), Arc::clone(&unhang));

                let requests =
                    fill_queue(&router, concurrency, depth, &metrics, meter_prefix).await;

                let concurrency = concurrency as usize;
                debug!("freeing up one slot in the queue");
                unhang.notify_one();
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth - 1).await;

                debug!("sending new request, should be queued");
                let request_router = router.clone();
                let request = tokio::spawn(async move { send_request(&request_router).await });

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
                let response = send_request(&router).await;
                assert_eq!(response.status(), StatusCode::OK);

                debug!("waiting for futures to terminate");
                for handle in requests {
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
                let metrics = InMemoryMetricInfrastructure::new();
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
                let router = hanging_router(Arc::clone(&queue), Arc::clone(&unhang));

                let requests =
                    fill_queue(&router, concurrency, depth, &metrics, meter_prefix).await;

                debug!("sending request, should fail");
                let response = send_request(&router).await;
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

                debug!("draining the queue");
                while get_outstanding_requests_gauge(&metrics, meter_prefix).await > Some(0) {
                    unhang.notify_one();
                }
                for handle in requests {
                    handle.await.unwrap();
                }

                debug!("sending request, should succeed");
                unhang.notify_one();
                let response = send_request(&router).await;
                assert_eq!(response.status(), StatusCode::OK);

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
                let queue = Arc::new(
                    LIFORequestQueue::new(concurrency, depth, &metrics.meter, meter_prefix, None)
                        .unwrap(),
                );
                let router = hanging_router(Arc::clone(&queue), Arc::clone(&unhang));

                let requests =
                    fill_queue(&router, concurrency, depth, &metrics, meter_prefix).await;

                let concurrency = concurrency as usize;
                debug!("freeing up one slot in the queue");
                unhang.notify_one();
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth - 1).await;

                debug!("sending new request, should be queued");
                // Build a new router that uses the same queue but a non-hanging handler
                let request_queue = Arc::clone(&queue);
                let new_router = Router::new()
                    .route("/", get_route(|| async { StatusCode::OK }))
                    .layer(axum::middleware::from_fn_with_state(
                        request_queue,
                        lifo_queue_middleware,
                    ));
                let new_router_clone = new_router.clone();
                let request = tokio::spawn(async move { send_request(&new_router_clone).await });

                debug!("waiting for new request to be queued");
                wait_for(&metrics, meter_prefix, |q| q == concurrency + depth).await;

                debug!("allowing one random request to proceed");
                unhang.notify_one();

                debug!("new request should be immediately processed");
                let response = request.await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);

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
            let metrics = InMemoryMetricInfrastructure::new();
            let concurrency = 1;
            let depth = 1;
            let timeout_duration = Duration::from_millis(100);

            let queue = Arc::new(
                LIFORequestQueue::new(
                    concurrency,
                    depth,
                    &metrics.meter,
                    meter_prefix,
                    Some(timeout_duration),
                )
                .unwrap(),
            );

            let unhang = Arc::new(Notify::new());
            let router = hanging_router(Arc::clone(&queue), Arc::clone(&unhang));

            // Fill up the active slots (concurrency) but leave queue empty
            let mut requests = Vec::new();
            for _ in 0..concurrency {
                let router = router.clone();
                requests.push(tokio::spawn(async move { send_request(&router).await }));
            }

            // Wait for all active slots to be filled
            wait_for(&metrics, meter_prefix, |q| q == concurrency as usize).await;

            // Now make a request that will be queued and should timeout
            let start = Instant::now();
            let result = send_request(&router).await;
            let elapsed = start.elapsed();

            // Should have timed out with TooManyRequests status
            assert_eq!(
                result.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "Expected TooManyRequests (429) but got {:?}",
                result.status()
            );
            // Should have taken approximately the timeout duration (with some tolerance)
            assert!(
                elapsed >= timeout_duration
                    && elapsed < timeout_duration + Duration::from_millis(200),
                "Request took {elapsed:?}, expected around {timeout_duration:?}"
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
