//! This crate contains functionality useful for Janus integration tests.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time,
};

use janus_aggregator_core::task::BatchMode;
use janus_client::OhttpConfig;
use janus_collector::AuthenticationToken;
use janus_core::{hpke::HpkeKeypair, vdaf::VdafInstance};
use janus_messages::{Interval, TaskId, TimePrecision};
use url::Url;

pub mod client;
pub mod interop_api;
pub mod janus;

/// Task parameters needed for an integration test. This encompasses the parameters used by either
/// the client or collector.
pub struct TaskParameters {
    pub task_id: TaskId,
    pub endpoint_fragments: EndpointFragments,
    pub batch_mode: BatchMode,
    pub vdaf: VdafInstance,
    pub min_batch_size: u64,
    pub time_precision: TimePrecision,
    /// The task's `task_info`, sourced from the provisioned task so the client and collector bind
    /// a byte-identical `TaskConfiguration` into their HPKE AADs.
    pub task_info: Vec<u8>,
    /// The optional task interval, for the same byte-identity reason.
    pub task_interval: Option<Interval>,
    pub collector_hpke_keypair: HpkeKeypair,
    pub collector_auth_token: AuthenticationToken,
    pub collector_max_interval: time::Duration,
    pub collector_max_elapsed_time: time::Duration,
}

/// Components of one aggregator's DAP endpoint.
#[derive(Debug)]
pub enum AggregatorEndpointFragments {
    /// The aggregator is in a Kind cluster, reached from the host via a port forward on localhost
    /// (ephemeral port, supplied later) and from within the cluster at its service name on port
    /// 8080. The scheme is always 'http:'.
    VirtualNetwork { host: String, path: String },
    /// The aggregator is in a Docker network, serving on `port` both within the network (at `host`)
    /// and from the host (via a fixed `host:port -> container:port` mapping). The single
    /// `http://{host}:{port}{path}` URL is byte-identical for all parties; the host reaches it by
    /// resolving `host` to loopback. The scheme is always 'http:'.
    DockerNetwork {
        host: String,
        port: u16,
        path: String,
    },
    /// The aggregator is running on localhost. No port forwarding is involved, so the same URL is
    /// used in all circumstances. The port number will be supplied later. The scheme is assumed to
    /// always be 'http:'.
    Localhost { path: String },
    /// The aggregator is running remotely, accessible at some URL. No port forwarding is involved,
    /// and the remote port and scheme are set by the URL.
    Remote { url: Url },
}

impl AggregatorEndpointFragments {
    /// Provides the URL for the aggregator's endpoint from the perspective of the host. If the
    /// aggregator is in a virtual network, this will use a port forward, with the provided port
    /// number. If the aggregator itself is running on the host, it will use the provided port
    /// number as well. If the aggregator is running remotely, the port number is ignored and the
    /// URL is returned.
    pub fn endpoint_for_host(&self, port: u16) -> Url {
        match self {
            AggregatorEndpointFragments::VirtualNetwork { path, .. }
            | AggregatorEndpointFragments::Localhost { path } => {
                Url::parse(&format!("http://127.0.0.1:{port}{path}")).unwrap()
            }
            AggregatorEndpointFragments::DockerNetwork { host, port, path } => {
                Url::parse(&format!("http://{host}:{port}{path}")).unwrap()
            }
            AggregatorEndpointFragments::Remote { url } => url.clone(),
        }
    }

    /// Provides the URL for the aggregator's endpoint from the perspective of another protocol
    /// participant on the virtual network. If the aggregator is in a virtual network, this will use
    /// the configured hostname and port 8080. If the aggregator is running on the host, it will
    /// panic.
    pub fn endpoint_for_virtual_network(&self) -> Url {
        match self {
            AggregatorEndpointFragments::VirtualNetwork { host, path } => {
                Url::parse(&format!("http://{host}:8080{path}")).unwrap()
            }
            AggregatorEndpointFragments::DockerNetwork { host, port, path } => {
                Url::parse(&format!("http://{host}:{port}{path}")).unwrap()
            }
            AggregatorEndpointFragments::Localhost { .. } => panic!(
                "cannot combine an aggregator running on localhost with a client or leader running \
                 in a virtual network"
            ),
            AggregatorEndpointFragments::Remote { .. } => {
                panic!("Cannot connect to remote aggregator on virtual network")
            }
        }
    }

    /// Set the path component.
    pub fn set_path(&mut self, path: String) {
        match self {
            AggregatorEndpointFragments::VirtualNetwork {
                path: self_path, ..
            }
            | AggregatorEndpointFragments::DockerNetwork {
                path: self_path, ..
            }
            | AggregatorEndpointFragments::Localhost { path: self_path } => *self_path = path,
            AggregatorEndpointFragments::Remote { .. } => {
                panic!("cannot set path for remote aggregator")
            }
        }
    }

    /// Set the serving port. Only valid for [`AggregatorEndpointFragments::DockerNetwork`].
    pub fn set_port(&mut self, port: u16) {
        match self {
            AggregatorEndpointFragments::DockerNetwork {
                port: self_port, ..
            } => *self_port = port,
            _ => panic!("only DockerNetwork endpoints have a settable port"),
        }
    }
}

/// Components of DAP endpoints for a leader and helper aggregator.
pub struct EndpointFragments {
    pub leader: AggregatorEndpointFragments,
    pub helper: AggregatorEndpointFragments,
    pub ohttp_config: Option<OhttpConfig>,
}

impl EndpointFragments {
    /// Provides the DAP endpoint URL for the leader aggregator to be used from the host. This
    /// requires an ephemeral port number, from either the aggregator itself or a port forward for
    /// the aggregator.
    pub fn leader_endpoint_for_host(&self, leader_port: u16) -> Url {
        self.leader.endpoint_for_host(leader_port)
    }

    /// Provides the DAP endpoint URL for both aggregators to be used from the host. This requires
    /// ephemeral port numbers for each.
    pub fn endpoints_for_host_client(&self, leader_port: u16, helper_port: u16) -> (Url, Url) {
        (
            self.leader.endpoint_for_host(leader_port),
            self.helper.endpoint_for_host(helper_port),
        )
    }

    /// Provides the DAP endpoint URL for both aggregators to be used from within the virtual
    /// network. This will panic if either aggregator is on localhost instead of in the virtual
    /// network.
    pub fn endpoints_for_virtual_network_client(&self) -> (Url, Url) {
        (
            self.leader.endpoint_for_virtual_network(),
            self.helper.endpoint_for_virtual_network(),
        )
    }

    /// Leader and helper endpoints, and an optional HTTP client, for an in-process client or
    /// collector on the host. For [`AggregatorEndpointFragments::DockerNetwork`] aggregators this
    /// returns the byte-identical virtual-network endpoints plus a client that resolves their
    /// hostnames to loopback; otherwise the localhost port-forward endpoints and no client.
    pub fn in_process_config(
        &self,
        leader_port: u16,
        helper_port: u16,
    ) -> (Url, Url, Option<reqwest::Client>) {
        match (&self.leader, &self.helper) {
            (
                AggregatorEndpointFragments::DockerNetwork {
                    host: leader_host,
                    port: leader_serving_port,
                    ..
                },
                AggregatorEndpointFragments::DockerNetwork {
                    host: helper_host,
                    port: helper_serving_port,
                    ..
                },
            ) => {
                let http_client = reqwest::Client::builder()
                    .resolve(
                        leader_host,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, *leader_serving_port)),
                    )
                    .resolve(
                        helper_host,
                        SocketAddr::from((Ipv4Addr::LOCALHOST, *helper_serving_port)),
                    )
                    .build()
                    .unwrap();
                (
                    self.leader.endpoint_for_virtual_network(),
                    self.helper.endpoint_for_virtual_network(),
                    Some(http_client),
                )
            }
            _ => (
                self.leader.endpoint_for_host(leader_port),
                self.helper.endpoint_for_host(helper_port),
                None,
            ),
        }
    }
}
