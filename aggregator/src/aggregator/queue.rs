use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

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
use tracing::warn;
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
    /// The tokio task that does most of the work.
    dispatcher: Option<JoinHandle<()>>,

    /// Sends messages to the dispatcher task.
    dispatcher_tx: mpsc::UnboundedSender<DispatcherMessage>,

    /// Generates unique ticket IDs, used to identify tickets in the queue.
    id_generator: TicketIdGenerator,
}

impl LIFORequestQueue {
    /// Creates a new [`Self`].
    ///
    /// `concurrency` must be greater than zero.
    pub fn new(concurrency: u32, depth: usize, meter: &Meter) -> Result<Self, Error> {
        if concurrency < 1 {
            return Err(Error::InvalidConfiguration(
                "concurrency must be greater than 0",
            ));
        }

        let (message_tx, message_rx) = mpsc::unbounded_channel();
        let id_generator = Default::default();
        let metrics = Metrics::new(meter);
        let dispatcher = Some(Self::dispatcher(message_rx, concurrency, depth, metrics));

        Ok(Self {
            dispatcher,
            id_generator,
            dispatcher_tx: message_tx,
        })
    }

    fn dispatcher(
        mut dispatcher_rx: mpsc::UnboundedReceiver<DispatcherMessage>,
        concurrency: u32,
        depth: usize,
        metrics: Metrics,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            // Use a BTreeMap to allow for cancellation (i.e. removal) of tickets in sublinear
            // time.
            let mut stack: BTreeMap<TicketId, PermitTx> = BTreeMap::new();

            // Unwrap safety: conversion only fails on architectures where usize is less than
            // 32-bits.
            let semaphore = Arc::new(Semaphore::new(concurrency.try_into().unwrap()));

            // Unwrap safety: the semaphore is never closed.
            let mut permits = Arc::clone(&semaphore)
                .acquire_many_owned(concurrency)
                .await
                .unwrap();

            loop {
                let semaphore = Arc::clone(&semaphore);
                select! {
                    Some(message) = dispatcher_rx.recv() => {
                        match message {
                            DispatcherMessage::Enqueue(id, permit_tx) => {
                                match permits.split(1) {
                                    Some(permit) => {
                                        permit_tx.send(Ok(permit));
                                    },
                                    None => {
                                        if stack.len() < depth {
                                            let result = stack.insert(id, permit_tx);
                                            assert!(result.is_none(), "ticket IDs must be unique");
                                        } else {
                                            permit_tx.send(Err(Error::TooManyRequests));
                                        }
                                    },
                                }
                            },
                            DispatcherMessage::Dequeue(id) => {
                                stack.remove(&id);
                            },
                        }
                    }

                    Ok(permit) = semaphore.acquire_owned() => {
                        match stack.pop_last() {
                            Some((_, permit_tx)) => {
                                permit_tx.send(Ok(permit));
                            },
                            None => {
                                permits.merge(permit);
                            },
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

    fn acquire(&self) -> Result<Ticket, Error> {
        let id = self.id_generator.next();
        let (permit_tx, permit_rx) = oneshot::channel();
        let ticket = Ticket {
            id,
            permit_rx: Some(permit_rx),
            cancel_tx: self.dispatcher_tx.clone(),
        };
        self.dispatcher_tx
            .send(DispatcherMessage::Enqueue(id, PermitTx(permit_tx)))
            // We don't necessarily panic because the dispatcher task could be shutdown as part of
            // process shutdown, while a request is in flight.
            .map_err(|_| Error::Internal("dispatcher task died".to_string()))?;
        Ok(ticket)
    }
}

impl Drop for LIFORequestQueue {
    fn drop(&mut self) {
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.abort();
        }
    }
}

/// Identifies a ticket in the queue.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
struct TicketId(u64);

/// Simple generator for unique ticket numbers. Ticket numbers are unique as long as there aren't
/// more than [`u64`] entries in the queue, at which point you've run out of memory.
///
/// This counter also wraps on overflow. In practical usage, this shouldn't matter since at 1M QPS
/// civilization will probably have ended by the time overflow occurs.
#[derive(Debug, Default)]
struct TicketIdGenerator(AtomicU64);

impl TicketIdGenerator {
    fn next(&self) -> TicketId {
        TicketId(self.0.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug)]
enum DispatcherMessage {
    Enqueue(TicketId, PermitTx),
    Dequeue(TicketId),
}

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

/// Handler-side ticket which is used to get in the queue.
#[derive(Debug)]
struct Ticket {
    id: TicketId,
    permit_rx: Option<PermitRx>,
    cancel_tx: mpsc::UnboundedSender<DispatcherMessage>,
}

impl Ticket {
    /// Waits for the ticket to be called. Returns an [`OwnedSemaphorePermit`] which should be
    /// dropped to signal that the request is done.
    ///
    /// # Panics
    ///
    /// Panics if it is called more than once.
    async fn wait(&mut self) -> Result<OwnedSemaphorePermit, Error> {
        self.permit_rx
            .take()
            .unwrap()
            .await
            .map_err(|err| Error::Internal(format!("dispatcher task died: {}", err)))?
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.permit_rx.is_some() {
            let _ = self
                .cancel_tx
                .send(DispatcherMessage::Dequeue(self.id))
                .map_err(|err| warn!("failed to send cancellation message: {:?}", err));
        }
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
        match self.queue.acquire() {
            Ok(mut ticket) => match conn.cancel_on_disconnect(ticket.wait()).await {
                Some(permit) => match permit {
                    Ok(_permit) => self.handler.run(conn).await,
                    Err(err) => err.run(conn).await,
                },
                None => Error::ClientDisconnected.run(conn).await,
            },
            Err(err) => err.run(conn).await,
        }
    }
}

/// Convenience function for wrapping a handler with a [`LIFOQueueHandler`].
pub fn queued_lifo<H: Handler>(queue: Arc<LIFORequestQueue>, handler: H) -> impl Handler {
    LIFOQueueHandler::new(queue, handler)
}

struct Metrics {
    outstanding_requests: Gauge<u64>,
}

impl Metrics {
    const OUTSTANDING_REQUESTS_METRIC_NAME: &'static str = "janus_aggregator_outstanding_requests";

    fn new(meter: &Meter) -> Self {
        Self {
            outstanding_requests: meter
                .u64_gauge(Self::OUTSTANDING_REQUESTS_METRIC_NAME)
                .with_description(concat!(
                    "The approximate number of requests currently being serviced by the ",
                    "aggregator."
                ))
                .with_unit("{request}")
                .init(),
        }
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
    use futures::future::join_all;
    use janus_aggregator_core::test_util::noop_meter;
    use janus_core::test_util::install_test_trace_subscriber;
    use opentelemetry_sdk::metrics::data::Gauge;
    use quickcheck::{Arbitrary, TestResult};
    use quickcheck_macros::quickcheck;
    use tokio::{
        runtime::{Builder as RuntimeBuilder, Runtime},
        sync::Notify,
        task::{yield_now, JoinHandle},
        time::timeout,
    };
    use tracing::debug;
    use trillium::{Conn, Handler, Status};
    use trillium_testing::{assert_ok, assert_status, methods::get};

    use crate::{
        aggregator::queue::{queued_lifo, LIFORequestQueue, Metrics},
        metrics::test_util::InMemoryMetricsInfrastructure,
    };

    /// Some tests busy loop waiting for a condition to become true. Avoid hanging tests
    /// indefinitely by wrapping those tests in a timeout.
    const TEST_TIMEOUT: Duration = Duration::from_secs(15);

    async fn get_outstanding_requests_gauge(
        metrics: &InMemoryMetricsInfrastructure,
    ) -> Option<usize> {
        Some(
            metrics
                .collect()
                .await
                .get(Metrics::OUTSTANDING_REQUESTS_METRIC_NAME)?
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
        while get_outstanding_requests_gauge(metrics).await != Some(concurrency as usize + depth) {
            yield_now().await;
        }

        requests
    }

    #[derive(Debug, Clone, Copy)]
    struct Parameters {
        /// In the making of this code, some bugs were uncovered by running on a different runtime
        /// flavor. Test both runtime flavors.
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
        fn build(&self) -> Runtime {
            match self {
                RuntimeFlavor::CurrentThread => RuntimeBuilder::new_current_thread(),
                RuntimeFlavor::MultiThread => RuntimeBuilder::new_multi_thread(),
            }
            .enable_all()
            .build()
            .unwrap()
        }
    }

    #[quickcheck]
    fn quickcheck_lifo_concurrency(parameters: Parameters) {
        install_test_trace_subscriber();
        debug!(?parameters, "quickcheck_lifo_concurrency parameters");
        let Parameters {
            runtime_flavor,
            depth,
            concurrency,
            requests,
        } = parameters;

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

        runtime_flavor.build().block_on(async move {
            timeout(TEST_TIMEOUT, async move {
                let queue =
                    Arc::new(LIFORequestQueue::new(concurrency, depth, &noop_meter()).unwrap());
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
            })
            .await
            .unwrap();
        });
    }

    #[quickcheck]
    fn quickcheck_lifo_cancel(parameters: Parameters) {
        install_test_trace_subscriber();
        debug!(?parameters, "quickcheck_lifo_cancel parameters");
        let Parameters {
            runtime_flavor,
            depth,
            concurrency,
            ..
        } = parameters;

        runtime_flavor.build().block_on(async move {
            timeout(TEST_TIMEOUT, async move {
                let metrics = InMemoryMetricsInfrastructure::new();
                let unhang = Arc::new(Notify::new());
                let queue =
                    Arc::new(LIFORequestQueue::new(concurrency, depth, &metrics.meter).unwrap());
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    HangingHandler {
                        unhang: Arc::clone(&unhang),
                    },
                ));

                let requests = fill_queue(Arc::clone(&handler), concurrency, depth, &metrics).await;

                debug!("cancelling outstanding requests");
                requests.iter().for_each(|request| request.abort());

                debug!("waiting for requests to be cancelled");
                while get_outstanding_requests_gauge(&metrics).await > Some(0) {
                    yield_now().await;
                }

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
            })
            .await
            .unwrap();
        });
    }

    #[quickcheck]
    fn quickcheck_lifo_full(parameters: Parameters) {
        install_test_trace_subscriber();
        debug!(?parameters, "quickcheck_lifo_full parameters");
        let Parameters {
            runtime_flavor,
            depth,
            concurrency,
            ..
        } = parameters;

        runtime_flavor.build().block_on(async move {
            timeout(TEST_TIMEOUT, async move {
                let unhang = Arc::new(Notify::new());
                let metrics = InMemoryMetricsInfrastructure::new();
                let queue =
                    Arc::new(LIFORequestQueue::new(concurrency, depth, &metrics.meter).unwrap());
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    HangingHandler {
                        unhang: Arc::clone(&unhang),
                    },
                ));

                let requests = fill_queue(Arc::clone(&handler), concurrency, depth, &metrics).await;

                debug!("sending request, should fail");
                let request = get("/").run_async(&handler).await;
                assert_status!(request, Status::ServiceUnavailable);

                debug!("draining the queue");
                while get_outstanding_requests_gauge(&metrics).await > Some(0) {
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
            })
            .await
            .unwrap()
        });
    }

    #[quickcheck]
    fn quickcheck_lifo(parameters: Parameters) -> TestResult {
        install_test_trace_subscriber();
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

        runtime_flavor.build().block_on(async move {
            timeout(TEST_TIMEOUT, async move {
                let unhang = Arc::new(Notify::new());
                let metrics = InMemoryMetricsInfrastructure::new();
                let queue =
                    Arc::new(LIFORequestQueue::new(concurrency, depth, &metrics.meter).unwrap());
                let handler = Arc::new(queued_lifo(
                    Arc::clone(&queue),
                    HangingHandler {
                        unhang: Arc::clone(&unhang),
                    },
                ));

                let requests = fill_queue(Arc::clone(&handler), concurrency, depth, &metrics).await;

                debug!("freeing up one slot in the queue");
                unhang.notify_one();
                while get_outstanding_requests_gauge(&metrics).await
                    != Some(concurrency as usize + depth - 1)
                {
                    yield_now().await;
                }

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
                while get_outstanding_requests_gauge(&metrics).await
                    != Some(concurrency as usize + depth)
                {
                    yield_now().await;
                }

                debug!("allowing one random request to proceed");
                unhang.notify_one();

                debug!("new request should be immediately processed");
                let request = request.await.unwrap();
                assert_ok!(request);

                debug!("draining the queue");
                while get_outstanding_requests_gauge(&metrics).await > Some(0) {
                    unhang.notify_one();
                    yield_now().await;
                }

                debug!("waiting for futures to terminate");
                for handle in requests {
                    handle.await.unwrap();
                }

                debug!("shutting down metrics");
                metrics.shutdown().await;

                TestResult::passed()
            })
            .await
            .unwrap()
        })
    }
}
