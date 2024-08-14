use std::{
    borrow::Cow,
    sync::{Arc, Mutex, OnceLock},
};

use regex::bytes::Regex;
use tracing::error;
use trillium::{Conn, Handler, Status};
use trillium_macros::Handler;

/// A [`Handler`] wrapper that can be configured to drop requests or responses.
#[derive(Handler)]
pub(super) struct FaultInjectorHandler<H> {
    #[handler(except = [run, before_send, name])]
    inner: H,

    /// Flag to inject an error before request handling. This will skip running the wrapped
    /// `Handler`.
    error_before: Arc<Mutex<bool>>,

    /// Flag to inject an error after request handling. This will drop the response and replace it
    /// with an error response.
    error_after: Arc<Mutex<bool>>,
}

impl<H> FaultInjectorHandler<H> {
    pub fn new(handler: H) -> Self {
        Self {
            inner: handler,
            error_before: Arc::new(Mutex::new(false)),
            error_after: Arc::new(Mutex::new(false)),
        }
    }

    pub fn controller(&self) -> FaultInjector {
        FaultInjector {
            error_before: Arc::clone(&self.error_before),
            error_after: Arc::clone(&self.error_after),
        }
    }
}

struct FaultInjectorMarker;

impl<H: Handler> FaultInjectorHandler<H> {
    async fn run(&self, mut conn: Conn) -> Conn {
        conn.insert_state(FaultInjectorMarker);
        if *self.error_before.lock().unwrap() {
            conn.with_status(Status::InternalServerError)
        } else {
            self.inner.run(conn).await
        }
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        let mut conn = self.inner.before_send(conn).await;
        if conn.state::<FaultInjectorMarker>().is_some() && *self.error_after.lock().unwrap() {
            conn.set_status(Status::InternalServerError);
            let header_names = conn
                .response_headers()
                .iter()
                .map(|(name, _)| name.to_owned())
                .collect::<Vec<_>>();
            conn.response_headers_mut().remove_all(header_names);
            conn.set_body("");
        }
        conn
    }

    fn name(&self) -> Cow<'static, str> {
        format!("FaultInjectorHandler({})", std::any::type_name::<H>()).into()
    }
}

/// This controls a [`FaultInjectorHandler`].
pub(super) struct FaultInjector {
    error_before: Arc<Mutex<bool>>,
    error_after: Arc<Mutex<bool>>,
}

impl FaultInjector {
    /// Disable all fault injection.
    pub fn reset(&self) {
        *self.error_before.lock().unwrap() = false;
        *self.error_after.lock().unwrap() = false;
    }

    /// Inject an error before request handling. This will skip running the wrapped `Handler`.
    pub fn error_before(&self) {
        *self.error_before.lock().unwrap() = true;
    }

    /// Inject an error after request handling. This will drop the response and replace it with an
    /// error response.
    pub fn error_after(&self) {
        *self.error_after.lock().unwrap() = true;
    }
}

/// A [`Handler`] wrapper that inspects request and response bodies, in order to trigger test failures.
#[derive(Handler)]
pub(super) struct InspectHandler<H> {
    #[handler(except = [run, before_send, name])]
    inner: H,
    failure: Arc<Mutex<bool>>,
}

impl<H> InspectHandler<H> {
    pub fn new(handler: H) -> Self {
        Self {
            inner: handler,
            failure: Arc::new(Mutex::new(false)),
        }
    }

    pub fn monitor(&self) -> InspectMonitor {
        InspectMonitor {
            failure: Arc::clone(&self.failure),
        }
    }
}

struct InspectMarker;

impl<H: Handler> InspectHandler<H> {
    async fn run(&self, mut conn: Conn) -> Conn {
        conn.insert_state(InspectMarker);
        self.inner.run(conn).await
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        let mut conn = self.inner.before_send(conn).await;
        if conn.state::<InspectMarker>().is_some() {
            if let Some(status) = conn.status() {
                if status.is_server_error() {
                    error!(?status, "server error");
                    *self.failure.lock().unwrap() = true;
                }
            }
            if conn.status() == Some(Status::Conflict) {
                error!("409 Conflict response");
                *self.failure.lock().unwrap() = true;
            }
            if conn.path().ends_with("/aggregate_shares") {
                inspect_response_body(&mut conn, |bytes| {
                    static ONCE: OnceLock<Regex> = OnceLock::new();
                    let batch_mismatch_regex = ONCE.get_or_init(|| {
                        Regex::new("urn:ietf:params:ppm:dap:error:batchMismatch").unwrap()
                    });
                    if batch_mismatch_regex.is_match(bytes) {
                        error!("batch mismatch response");
                        *self.failure.lock().unwrap() = true;
                    }
                })
                .await;
            }
        }
        conn
    }

    fn name(&self) -> Cow<'static, str> {
        format!("InspectHandler({})", std::any::type_name::<H>()).into()
    }
}

/// Takes the response body from a connection, runs the provided closure on it, and replaces the
/// response body. If no body has been set yet, the closure is not run.
async fn inspect_response_body(conn: &mut Conn, f: impl Fn(&[u8])) {
    if let Some(body) = conn.take_response_body() {
        let bytes = body.into_bytes().await.unwrap();
        f(&bytes);
        conn.set_body(bytes);
    }
}

pub(super) struct InspectMonitor {
    failure: Arc<Mutex<bool>>,
}

impl InspectMonitor {
    pub fn has_failed(&self) -> bool {
        *self.failure.lock().unwrap()
    }
}
