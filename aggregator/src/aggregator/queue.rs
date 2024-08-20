use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};

use tokio::{
    sync::{
        mpsc,
        oneshot::{self},
        Notify, OwnedSemaphorePermit, Semaphore,
    },
    task::JoinHandle,
};
use tracing::warn;
use trillium::{Conn, Handler};
use trillium_macros::Handler;

use super::Error;

type Stack = Arc<StdMutex<Vec<Dispatcher>>>;

/// A queue that services requests in a LIFO manner, i.e. the most recent request is serviced first.
/// It bounds the total number of waiting requests, and the number of requests that can be run
/// concurrently. This is useful for adding backpressure and preventing the process from being
/// overwhelmed.
///
/// See https://encore.dev/blog/queueing for a rationale of LIFO request queuing.
///
/// Note the actual execution order of requests is not perfectly LIFO if the concurrency is >1,
/// because the order that request futures are scheduled and executed in is essentially
/// non-deterministic.
#[derive(Debug)]
pub struct LIFORequestQueue {
    /// Maximum size of the queue.
    depth: usize,

    /// LIFO data structure.
    stack: Stack,

    /// Notifies the dispatch task to wake up when a new ticket arrives in an empty stack.
    notifier: Arc<Notify>,

    /// Controls concurrency of requests.
    _semaphore: Arc<Semaphore>,

    /// Alerts tickets when they're ready.
    dispatcher: JoinHandle<()>,

    /// Generates unique ticket IDs, used to identify tickets in the queue.
    id_generator: TicketIdGenerator,

    /// Receives notifications when a request has given up on waiting in the queue.
    cancel_tx: mpsc::UnboundedSender<TicketId>,

    /// Services cancel notifications by directly removing cancelled tickets from the queue. This
    /// prevents cancelled tickets from taking up space in the queue and starving new requests.
    canceller: JoinHandle<()>,
}

impl LIFORequestQueue {
    /// Creates a new [`Self`].
    ///
    /// `concurrency` and `depth` must be greater than 0, and `depth` must be greater than or
    /// equal to `concurrency`.
    pub fn new(concurrency: usize, depth: usize) -> Result<Self, Error> {
        if concurrency < 1 {
            return Err(Error::InvalidConfiguration(
                "concurrency must be greater than 0",
            ));
        } else if depth < 1 {
            return Err(Error::InvalidConfiguration(
                "depth must be greater than zero",
            ));
        } else if concurrency > depth {
            // We enforce this property otherwise it leads to strange intermittent behavior, i.e.
            // rejecting requests due to the queue being full even though there's sufficient
            // concurrency slots open.
            return Err(Error::InvalidConfiguration(
                "depth must be greater than or equal to concurrency",
            ));
        }

        let stack: Stack = Default::default();
        let notifier = Arc::new(Notify::new());
        let (cancel_tx, cancel_rx) = mpsc::unbounded_channel();
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let dispatcher = Self::dispatcher(
            Arc::clone(&stack),
            Arc::clone(&notifier),
            Arc::clone(&semaphore),
        );
        let canceller = Self::canceller(Arc::clone(&stack), cancel_rx);
        let id_generator = Default::default();
        Ok(Self {
            depth,
            stack,
            notifier,
            _semaphore: semaphore,
            dispatcher,
            id_generator,
            cancel_tx,
            canceller,
        })
    }

    fn dispatcher(
        stack: Stack,
        notifier: Arc<Notify>,
        semaphore: Arc<Semaphore>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let semaphore = Arc::clone(&semaphore);

                // Unwrap safety: the semaphore is never dropped.
                let permit = semaphore.acquire_owned().await.unwrap();
                let dispatcher = {
                    // Unwrap safety: mutex poisoning
                    let mut stack = stack.lock().unwrap();
                    stack.pop()
                };
                match dispatcher {
                    Some(mut dispatcher) => {
                        dispatcher.send(permit);
                    }
                    None => {
                        // The queue is empty. Sleep here until we're notified that there's another
                        // ticket available to work on.
                        notifier.notified().await;
                    }
                }
            }
        })
    }

    fn canceller(stack: Stack, mut cancel_rx: mpsc::UnboundedReceiver<TicketId>) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(cancellation) = cancel_rx.recv().await {
                // Unwrap safety: mutex poisoning.
                let mut stack = stack.lock().unwrap();

                // For a Vec, this is worst case O(n) per cancelled request. We anticipate the
                // queue depth will be small, so cache locality should keep this relatively
                // performant.
                stack.retain(|dispatcher| dispatcher.id != cancellation);
            }
        })
    }

    fn acquire(&self) -> Result<Ticket, Error> {
        // Unwrap safety: mutex poisoning.
        let mut stack = self.stack.lock().unwrap();
        if stack.len() < self.depth {
            let (permit_tx, permit_rx) = oneshot::channel();
            let id = self.id_generator.next();
            let dispatcher = Dispatcher {
                id,
                permit_tx: Some(permit_tx),
            };
            let ticket = Ticket {
                id,
                permit_rx: Some(permit_rx),
                cancel_tx: self.cancel_tx.clone(),
            };

            stack.push(dispatcher);
            self.notifier.notify_waiters();
            Ok(ticket)
        } else {
            Err(Error::TooManyRequests)
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        // Unwrap safety: mutex poisoning.
        let stack = self.stack.lock().unwrap();
        stack.len()
    }

    #[cfg(test)]
    pub fn available_permits(&self) -> usize {
        self._semaphore.available_permits()
    }
}

impl Drop for LIFORequestQueue {
    fn drop(&mut self) {
        self.dispatcher.abort();
        self.canceller.abort();
    }
}

/// Identifies a ticket in the queue.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
struct TicketId(usize);

/// Simple generator for unique ticket numbers. Ticket numbers are unique as long as there aren't
/// more than [`usize`] entries in the queue, at which point you've run out of memory.
#[derive(Debug, Default)]
struct TicketIdGenerator(AtomicUsize);

impl TicketIdGenerator {
    fn next(&self) -> TicketId {
        TicketId(self.0.fetch_add(1, Ordering::Relaxed))
    }
}

/// Dispatcher-side ticket which is used to signal when the ticket is ready. Corresponds 1:1 with a
/// [`Ticket`].
#[derive(Debug)]
struct Dispatcher {
    /// Identifies the ticket in the queue.
    id: TicketId,

    /// Signals the [`Ticket`] holder that it may proceed.
    permit_tx: Option<oneshot::Sender<OwnedSemaphorePermit>>,
}

impl Dispatcher {
    fn send(&mut self, permit: OwnedSemaphorePermit) {
        // Unwrap safety: we should only send once on this channel.
        let _ = self
            .permit_tx
            .take()
            .unwrap()
            .send(permit)
            .map_err(|_| warn!("failed to dispatch, request cancelled?"));
    }
}

/// Handler-side ticket which is used to get in the queue.
#[derive(Debug)]
struct Ticket {
    id: TicketId,
    permit_rx: Option<oneshot::Receiver<OwnedSemaphorePermit>>,
    cancel_tx: mpsc::UnboundedSender<TicketId>,
}

impl Ticket {
    /// Waits for the ticket to be called. Returns an [`OwnedSemaphorePermit`] which should be
    /// dropped to signal that the request is done.
    async fn wait(&mut self) -> Result<OwnedSemaphorePermit, Error> {
        // Unwrap safety: wait() should only be called once.
        self.permit_rx
            .take()
            .unwrap()
            .await
            .map_err(|err| Error::Internal(format!("dispatcher task died: {}", err)))
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.permit_rx.is_some() {
            let _ = self
                .cancel_tx
                .send(self.id)
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
                Some(_permit) => self.handler.run(conn).await,
                None => Error::ClientDisconnected.run(conn).await,
            },
            Err(full) => full.run(conn).await,
        }
    }
}

/// Convenience function for wrapping a handler with a [`LIFOQueueHandler`].
pub fn queued_lifo<H: Handler>(queue: Arc<LIFORequestQueue>, handler: H) -> impl Handler {
    LIFOQueueHandler::new(queue, handler)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use backoff::{future::retry, ExponentialBackoff};
    use futures::future::join_all;
    use janus_core::test_util::install_test_trace_subscriber;
    use quickcheck::Arbitrary;
    use quickcheck_macros::quickcheck;
    use tokio::{
        runtime::{Builder as RuntimeBuilder, Runtime},
        sync::Semaphore,
        task::{yield_now, JoinHandle},
    };
    use tracing::debug;
    use trillium::{Handler, Status};
    use trillium_testing::{assert_ok, assert_status, methods::get};

    use crate::aggregator::queue::{queued_lifo, LIFORequestQueue};

    struct HangingHandler {
        unhang: Arc<Semaphore>,
    }

    #[async_trait]
    impl Handler for HangingHandler {
        async fn run(&self, conn: trillium::Conn) -> trillium::Conn {
            let _ = self.unhang.acquire().await;
            conn.ok("hello")
        }
    }

    async fn fill_queue(
        queue: Arc<LIFORequestQueue>,
        handler: Arc<impl Handler>,
        concurrency: usize,
        depth: usize,
    ) -> Vec<JoinHandle<()>> {
        let mut requests = Vec::new();
        for _ in 0..(concurrency + depth) {
            let handler = Arc::clone(&handler);
            requests.push(tokio::spawn({
                async move {
                    let backoff = ExponentialBackoff {
                        initial_interval: Duration::from_nanos(1),
                        max_interval: Duration::from_nanos(30),
                        multiplier: 2.0,
                        ..Default::default()
                    };
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

        // Wait until all semaphore permits are exhausted and the queue is full, indicating full
        // saturation.
        while queue.len() < depth || queue.available_permits() > 0 {
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
        concurrency: usize,
        requests: usize,
    }

    impl Arbitrary for Parameters {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let concurrency = u8::arbitrary(g) as usize + 1;
            let depth = concurrency + u8::arbitrary(g) as usize;
            let requests = (u16::arbitrary(g) / 10) as usize;
            Self {
                runtime_flavor: if bool::arbitrary(g) {
                    RuntimeFlavor::CurrentThread
                } else {
                    RuntimeFlavor::MultiThread
                },
                depth,
                concurrency,
                requests,
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

    // #[tokio::test]
    // async fn lifo_cancel_on_disconnect() {}

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
            max_concurrency: usize,
            concurrency: AtomicUsize,
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
            let queue = Arc::new(LIFORequestQueue::new(concurrency, depth).unwrap());
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
            let unhang = Arc::new(Semaphore::new(0));
            let queue = Arc::new(LIFORequestQueue::new(concurrency, depth).unwrap());
            let handler = Arc::new(queued_lifo(
                Arc::clone(&queue),
                HangingHandler {
                    unhang: Arc::clone(&unhang),
                },
            ));

            let requests =
                fill_queue(Arc::clone(&queue), Arc::clone(&handler), concurrency, depth).await;

            // Abort all outstanding requests.
            requests.iter().for_each(|request| request.abort());

            // Wait until the queue is empty.
            while queue.len() > 0 {
                yield_now().await;
            }

            unhang.close();
            let request = get("/").run_async(&handler).await;
            assert_ok!(request);

            for handle in requests {
                // These handles will return a JoinError, but we're moreso interested to see if
                // they've all terminated.
                let _ = handle.await;
            }
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
            let unhang = Arc::new(Semaphore::new(0));
            let queue = Arc::new(LIFORequestQueue::new(concurrency, depth).unwrap());
            let handler = Arc::new(queued_lifo(
                Arc::clone(&queue),
                HangingHandler {
                    unhang: Arc::clone(&unhang),
                },
            ));

            let requests =
                fill_queue(Arc::clone(&queue), Arc::clone(&handler), concurrency, depth).await;

            let request = get("/").run_async(&handler).await;
            assert_status!(request, Status::ServiceUnavailable);

            unhang.close();

            // Let the dispatcher get a turn on the scheduler.
            while queue.len() == depth {
                yield_now().await;
            }

            let request = get("/").run_async(&handler).await;
            assert_ok!(request);

            for handle in requests {
                handle.await.unwrap();
            }
        });
    }
}
