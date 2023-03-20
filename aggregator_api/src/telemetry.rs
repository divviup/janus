use opentelemetry::{
    global::meter,
    metrics::{Histogram, Unit},
    Context, KeyValue,
};
use std::{sync::Arc, time::Instant};
use trillium::{async_trait, Conn, Handler, Status};
use trillium_router::RouterConnExt;

pub struct Telemetry(Arc<Histogram<u64>>);

impl Telemetry {
    pub fn new() -> Self {
        Self(Arc::new(
            meter("janus_aggregator_api")
                .u64_histogram("http.server.duration")
                .with_description("Elapsed time handling incoming requests, by endpoint & status.")
                .with_unit(Unit::new("ms"))
                .init(),
        ))
    }
}

#[async_trait]
impl Handler for Telemetry {
    async fn run(&self, conn: Conn) -> Conn {
        conn
    }

    async fn before_send(&self, mut conn: Conn) -> Conn {
        let meter = Arc::clone(&self.0);
        let status = (conn.status().unwrap_or(Status::NotFound) as u16).to_string();
        let route = conn
            .route()
            .map(|rs| rs.to_string())
            .unwrap_or_else(|| String::from("no matched route"));
        let start_time = conn.inner().start_time();
        let method = conn.method().to_string();

        conn.inner_mut().after_send(move |_| {
            let duration = (Instant::now() - start_time)
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);

            meter.record(
                &Context::current(),
                duration,
                &[
                    KeyValue::new("http.route", route),
                    KeyValue::new("http.method", method),
                    KeyValue::new("http.status_code", status),
                ],
            )
        });
        conn
    }
}
