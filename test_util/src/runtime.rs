use futures::FutureExt;
use janus::Runtime;
use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    panic::{panic_any, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{
    sync::watch::{self, Sender},
    task::JoinHandle,
};

/// Tracks multiple instrumented [`Runtime`] objects, for use in tests. Each
/// [`TestRuntime`] keeps track of how many of its tasks have been completed,
/// and tests can wait until a given number of tasks finish. If any task
/// panics, this manager object will panic on drop, to ensure that the
/// relevant test fails and the task panics do not go unnoticed.
pub struct TestRuntimeManager<L> {
    map: HashMap<L, TestRuntime>,
}

impl<L> TestRuntimeManager<L> {
    pub fn new() -> TestRuntimeManager<L> {
        TestRuntimeManager {
            map: HashMap::new(),
        }
    }
}

impl<L> TestRuntimeManager<L>
where
    L: Eq + Hash,
{
    /// Construct or retrieve a [`TestRuntime`] with a given label.
    pub fn with_label(&mut self, label: L) -> TestRuntime {
        self.map.entry(label).or_default().clone()
    }

    /// Wait for the runtime with the given label to reach some number of
    /// completed tasks. Note that tasks that have already completed before
    /// this method is called are included in the count.
    pub async fn wait_for_completed_tasks(&mut self, label: L, target_count: usize) {
        let labeled_runtime = self.with_label(label);
        let mut receiver = labeled_runtime.inner.sender.subscribe();
        if *receiver.borrow_and_update() >= target_count {
            return;
        }
        loop {
            receiver.changed().await.expect(
                "The channel sender should not be dropped before waits have \
                finished, this likely indicates an issue with a test.",
            );
            if *receiver.borrow() >= target_count {
                break;
            }
        }
    }
}

impl<L> Default for TestRuntimeManager<L> {
    fn default() -> TestRuntimeManager<L> {
        TestRuntimeManager::new()
    }
}

impl<L> Drop for TestRuntimeManager<L> {
    fn drop(&mut self) {
        // Check if any panicking tasks were observed. By default, an error
        // message and backtrace will be printed, but we would like this to be
        // noisier in tests, and cause the main test thread to panic.
        for labeled_runtime in self.map.values() {
            if labeled_runtime.inner.any_panic.load(Ordering::Acquire) {
                panic!("An async task panicked");
            }
        }
    }
}

#[derive(Clone)]
pub struct TestRuntime {
    inner: Arc<Inner>,
}

struct Inner {
    any_panic: AtomicBool,
    sender: Sender<usize>,
}

impl TestRuntime {
    fn new() -> TestRuntime {
        let (channel, _) = watch::channel(0);
        TestRuntime {
            inner: Arc::new(Inner {
                any_panic: AtomicBool::new(false),
                sender: channel,
            }),
        }
    }
}

impl Default for TestRuntime {
    fn default() -> TestRuntime {
        TestRuntime::new()
    }
}

impl Runtime for TestRuntime {
    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let labeled_runtime = self.clone();
        tokio::task::spawn(async move {
            // If there is any non-UnwindSafe behavior in this future, it
            // won't be an issue because we will re-raise the panic after
            // making note of it. Nothing will have a chance to observe any
            // broken logical invariants.
            let res = AssertUnwindSafe(future).catch_unwind().await;
            labeled_runtime
                .inner
                .sender
                .send_modify(|counter| *counter += 1);
            match res {
                Ok(output) => output,
                Err(e) => {
                    labeled_runtime
                        .inner
                        .any_panic
                        .fetch_or(true, Ordering::Release);
                    panic_any(e);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Barrier;

    use super::{Runtime, TestRuntimeManager};

    #[tokio::test]
    async fn mock_runtime() {
        #[derive(PartialEq, Eq, Hash)]
        enum Label {
            A,
            B,
        }

        let mut runtime = TestRuntimeManager::<Label>::new();
        let runtime_a = runtime.with_label(Label::A);
        let runtime_b = runtime.with_label(Label::B);

        let barrier = Arc::new(Barrier::new(2));

        let handle_a_1 = runtime_a.spawn(std::future::ready(()));
        let handle_b_1 = runtime_b.spawn(std::future::ready(()));

        runtime.wait_for_completed_tasks(Label::A, 1).await;
        runtime.wait_for_completed_tasks(Label::B, 1).await;
        assert_eq!(*runtime_a.inner.sender.borrow(), 1);
        assert_eq!(*runtime_b.inner.sender.borrow(), 1);

        let handle_a_2 = runtime_a.spawn({
            let handle_a_3 = runtime_a.spawn(std::future::ready(()));
            let barrier = Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                handle_a_3
            }
        });

        assert_eq!(*runtime_a.inner.sender.borrow(), 1);
        barrier.wait().await;
        runtime.wait_for_completed_tasks(Label::A, 2).await;
        runtime.wait_for_completed_tasks(Label::A, 3).await;
        runtime.wait_for_completed_tasks(Label::A, 2).await;

        handle_a_1.await.unwrap();
        let handle_a_3 = handle_a_2.await.unwrap();
        handle_a_3.await.unwrap();
        handle_b_1.await.unwrap();
        assert_eq!(*runtime_a.inner.sender.borrow(), 3);
        assert_eq!(*runtime_b.inner.sender.borrow(), 1);
    }

    #[tokio::test]
    #[should_panic]
    async fn noisy_task_panic() {
        let mut runtime = TestRuntimeManager::<()>::new();
        let handle = runtime.with_label(()).spawn(async { &[0u8][..2] });
        let _ = handle.await;
        drop(runtime);
    }
}
