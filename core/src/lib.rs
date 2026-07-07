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
pub mod task_config;
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
const DAP_VERSION_IDENTIFIER: &str = "dap-18";

/// Extends [`Url`] with a helper for making a URL safe to use as a [`Url::join`] base.
pub trait UrlExt {
    /// Returns this URL, modified to end with a slash if it does not already.
    ///
    /// A base URL must end with a slash for [`Url::join`] to preserve its last path component.
    fn ensure_trailing_slash(self) -> Self;
}

impl UrlExt for Url {
    fn ensure_trailing_slash(mut self) -> Self {
        if !self.as_str().ends_with('/') {
            self.set_path(&format!("{}/", self.path()));
        }
        self
    }
}

/// Converts a [`janus_messages::Url`] into a [`url::Url`] ready for [`Url::join`], ensuring a
/// trailing slash so `join` does not drop the last path component.
///
/// The trailing-slash fixup applies only to this routing copy, never to the stored
/// [`janus_messages::Url`] — its exact bytes are bound into HPKE AADs and must not be re-encoded
/// (DAP-18 §4.1).
pub fn url_for_join(url: &janus_messages::Url) -> Result<Url, url::ParseError> {
    Ok(Url::try_from(url)?.ensure_trailing_slash())
}

/// Choose aws-lc-rs as the default rustls crypto provider. This is what's currently enabled by the
/// default Cargo feature. Specifying a default provider here prevents runtime errors if another
/// dependency also enables the ring feature.
pub fn initialize_rustls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
