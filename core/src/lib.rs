#![cfg_attr(docsrs, feature(doc_cfg))]

use std::future::Future;
use tokio::task::JoinHandle;
use url::Url;

pub mod auth_tokens;
pub mod cli;
pub mod dp;
pub mod hpke;
pub mod http;
pub mod report_id;
pub mod retries;
#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util;
pub mod time;
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
const DAP_VERSION_IDENTIFIER: &str = "dap-14";

/// Returns the given [`Url`], possibly modified to end with a slash.
///
/// Aggregator endpoint URLs should end with a slash if they will be used with [`Url::join`],
/// because that method will drop the last path component of the base URL if it does not end with a
/// slash.
pub fn url_ensure_trailing_slash(mut url: Url) -> Url {
    if !url.as_str().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    url
}

/// Choose aws-lc-rs as the default rustls crypto provider. This is what's currently enabled by the
/// default Cargo feature. Specifying a default provider here prevents runtime errors if another
/// dependency also enables the ring feature.
pub fn initialize_rustls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
