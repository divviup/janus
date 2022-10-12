use std::future::Future;
use tokio::task::JoinHandle;

pub mod hpke;
pub mod http;
pub mod report_id;
pub mod retries;
pub mod task;
#[cfg(feature = "test-util")]
pub mod test_util;
pub mod time;

/// This trait provides a mockable facade for [`tokio::task::spawn`].
pub trait Runtime {
    /// Spawn a future on a new task managed by an asynchronous runtime, and
    /// return a handle that can be used to await completion of that task.
    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

/// This type implements [`Runtime`] by directly calling [`tokio::task::spawn`].
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::task::spawn(future)
    }
}
