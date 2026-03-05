mod aggregate_share;
mod aggregation_job_continue;
mod aggregation_job_get;
mod aggregation_job_init;
mod collection_job;
mod helper_e2e;
mod hpke_config;
mod report;

use trillium_testing::prelude::*;

use crate::aggregator::http_handlers::test_util::HttpHandlerTest;

/// Verify that Trillium routes not matched by the Trillium router fall through to the
/// local axum server via the proxy bridge.
// TODO(#4283): Remove once a real endpoint has been migrated and tested.
#[tokio::test]
async fn axum_proxy_fallthrough() {
    let test = HttpHandlerTest::new().await;
    let mut conn = get("/internal/test/axum_ready")
        .run_async(&test.handler)
        .await;
    assert_eq!(conn.status(), Some(trillium::Status::Ok));
    let body = test_util::take_response_body(&mut conn).await;
    assert_eq!(body, b"axum OK");
}

use super::test_util;
