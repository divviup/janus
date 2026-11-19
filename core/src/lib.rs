#![cfg_attr(docsrs, feature(doc_cfg))]

use std::future::Future;

use tokio::task::JoinHandle;

pub mod auth_tokens;
pub mod cli;
pub mod dp;
pub mod hpke;
pub mod http;
pub mod messages;
pub mod report_id;
pub mod retries;
pub mod task_config;
#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util;
pub mod time;
pub mod url;
pub use url::{UrlExt, url_for_join};
pub mod vdaf;

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

pub mod taskprov {
    pub const TASKPROV_HEADER: &str = "dap-taskprov";
}

/// This value is used in a few places throughout the protocol to identify the draft of DAP being
/// implemented.
const DAP_VERSION_IDENTIFIER: &str = "dap-18";

/// Choose aws-lc-rs as the default rustls crypto provider. This is what's currently enabled by the
/// default Cargo feature. Specifying a default provider here prevents runtime errors if another
/// dependency also enables the ring feature.
pub fn initialize_rustls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
