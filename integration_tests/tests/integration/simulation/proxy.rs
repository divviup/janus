use std::sync::{Arc, LazyLock, Mutex};

use axum::{Router, body::Body, extract::Request, middleware, response::IntoResponse};
use http::StatusCode;
use regex::bytes::Regex;
use tracing::error;

/// Wraps an axum Router with fault injection middleware. Returns the wrapped router and a
/// controller to toggle faults.
pub(super) fn wrap_with_fault_injection(router: Router) -> (Router, FaultInjector) {
    let error_before = Arc::new(Mutex::new(false));
    let error_after = Arc::new(Mutex::new(false));

    let controller = FaultInjector {
        error_before: Arc::clone(&error_before),
        error_after: Arc::clone(&error_after),
    };

    let eb = Arc::clone(&error_before);
    let ea = Arc::clone(&error_after);
    let wrapped = router.layer(middleware::from_fn(move |request: Request, next: middleware::Next| {
        let eb = Arc::clone(&eb);
        let ea = Arc::clone(&ea);
        async move {
            if *eb.lock().unwrap() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let response = next.run(request).await;
            if *ea.lock().unwrap() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            response
        }
    }));

    (wrapped, controller)
}

/// This controls fault injection middleware.
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

    /// Inject an error before request handling.
    pub fn error_before(&self) {
        *self.error_before.lock().unwrap() = true;
    }

    /// Inject an error after request handling.
    pub fn error_after(&self) {
        *self.error_after.lock().unwrap() = true;
    }
}

/// Wraps an axum Router with inspection middleware. Returns the wrapped router and a monitor
/// to check for failures.
pub(super) fn wrap_with_inspect(router: Router) -> (Router, InspectMonitor) {
    let failure = Arc::new(Mutex::new(false));
    let monitor = InspectMonitor {
        failure: Arc::clone(&failure),
    };

    let wrapped = router.layer(middleware::from_fn(move |request: Request, next: middleware::Next| {
        let failure = Arc::clone(&failure);
        let is_aggregate_shares = request.uri().path().ends_with("/aggregate_shares");
        async move {
            let response = next.run(request).await;
            let status = response.status();

            if status.is_server_error() {
                error!(?status, "server error");
                *failure.lock().unwrap() = true;
            }
            if status == StatusCode::CONFLICT {
                error!("409 Conflict response");
                *failure.lock().unwrap() = true;
            }
            if is_aggregate_shares {
                // Collect the body to inspect it, then reconstruct the response
                let (parts, body) = response.into_parts();
                let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                static REGEX: LazyLock<Regex> = LazyLock::new(|| {
                    Regex::new("urn:ietf:params:ppm:dap:error:batchMismatch").unwrap()
                });
                if REGEX.is_match(&bytes) {
                    error!("batch mismatch response");
                    *failure.lock().unwrap() = true;
                }
                return http::Response::from_parts(parts, Body::from(bytes)).into_response();
            }
            response
        }
    }));

    (wrapped, monitor)
}

pub(super) struct InspectMonitor {
    failure: Arc<Mutex<bool>>,
}

impl InspectMonitor {
    pub fn has_failed(&self) -> bool {
        *self.failure.lock().unwrap()
    }
}
