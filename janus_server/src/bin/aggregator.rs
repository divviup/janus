use anyhow::{Context, Result};
use janus_server::{aggregator::aggregator_server, message::TaskId, trace::install_subscriber};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    install_subscriber().context("failed to install tracing subscriber")?;

    // TODO(issue #20): We should not hardcode the address we listen on and
    // should not randomly generate task IDs.
    let task_id = TaskId::random();
    let listen_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);

    let (bound_address, server) = aggregator_server(task_id, listen_address);
    info!(?task_id, ?bound_address, "running aggregator");

    server.await;

    unreachable!()
}
