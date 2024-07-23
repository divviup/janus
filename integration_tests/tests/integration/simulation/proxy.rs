use std::{
    borrow::Cow,
    sync::{Arc, Mutex},
};

use trillium::{Conn, Handler, Status};
use trillium_macros::Handler;

// TODO: should also snoop on request and response bodies, in order to trigger test failures.

/// A [`Handler`] wrapper that can be configured to drop requests or responses.
#[derive(Handler)]
pub(super) struct FaultInjectorHandler<H> {
    #[handler(except=[run, before_send, name])]
    inner: H,
    error_before: Arc<Mutex<bool>>,
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

struct Marker;

impl<H: Handler> FaultInjectorHandler<H> {
    async fn run(&self, mut conn: Conn) -> Conn {
        conn.insert_state(Marker);
        if *self.error_before.lock().unwrap() {
            conn.with_status(Status::InternalServerError)
        } else {
            self.inner.run(conn).await
        }
    }

    async fn before_send(&self, conn: Conn) -> Conn {
        let mut conn = self.inner.before_send(conn).await;
        if conn.state::<Marker>().is_some() && *self.error_after.lock().unwrap() {
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
        format!("FaultInjector({})", std::any::type_name::<H>()).into()
    }
}

/// This controls a [`FaultInjectorHandler`].
pub(super) struct FaultInjector {
    error_before: Arc<Mutex<bool>>,
    error_after: Arc<Mutex<bool>>,
}

impl FaultInjector {
    pub fn reset(&self) {
        *self.error_before.lock().unwrap() = false;
        *self.error_after.lock().unwrap() = false;
    }

    pub fn error_before(&self) {
        *self.error_before.lock().unwrap() = true;
    }

    pub fn error_after(&self) {
        *self.error_after.lock().unwrap() = true;
    }
}
