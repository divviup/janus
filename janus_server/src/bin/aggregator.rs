use anyhow::{anyhow, Context, Result};
use chrono::Duration;
use janus_server::{
    aggregator::aggregator_server,
    hpke::{HpkeRecipient, Label},
    message::Role,
    message::TaskId,
    time::RealClock,
    trace::install_subscriber,
};
use std::{
    env::args,
    iter::Iterator,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let role = match args().nth(1).as_deref() {
        None | Some("leader") => Role::Leader,
        Some("helper") => Role::Helper,
        Some(r) => {
            return Err(anyhow!("unsupported role {}", r));
        }
    };

    install_subscriber().context("failed to install tracing subscriber")?;

    // TODO(issue #20): We should not hardcode the address we listen on and
    // should not randomly generate task IDs.
    let task_id = TaskId::random();
    let hpke_recipient =
        HpkeRecipient::generate(task_id, Label::InputShare, Role::Client, Role::Leader);
    let listen_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);

    let (bound_address, server) = aggregator_server(
        RealClock::default(),
        Duration::minutes(10),
        role,
        hpke_recipient,
        listen_address,
    )
    .context("failed to create aggregator server")?;
    info!(?task_id, ?bound_address, "running aggregator");

    server.await;

    Ok(())
}
