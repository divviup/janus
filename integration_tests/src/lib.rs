//! This crate contains functionality useful for Janus integration tests.

use janus_aggregator_core::task::QueryType;
use janus_collector::AuthenticationToken;
use janus_core::{hpke::HpkeKeypair, vdaf::VdafInstance};
use janus_messages::{Duration, TaskId};
use url::Url;

pub mod client;
pub mod daphne;
pub mod interop_api;
pub mod janus;

/// Task parameters needed for an integration test. This encompasses the parameters used by either
/// the client or collector.
pub struct TaskParameters {
    pub task_id: TaskId,
    pub endpoint_fragments: EndpointFragments,
    pub query_type: QueryType,
    pub vdaf: VdafInstance,
    pub min_batch_size: u64,
    pub time_precision: Duration,
    pub collector_hpke_keypair: HpkeKeypair,
    pub collector_auth_token: AuthenticationToken,
}

/// Components of DAP endpoints for a leader and helper aggregator. By default, the scheme is
/// assumed to be `http:`, and the port number is assumed to be 8080.
pub struct EndpointFragments {
    pub leader_endpoint_host: String,
    pub leader_endpoint_path: String,
    pub helper_endpoint_host: String,
    pub helper_endpoint_path: String,
}

impl EndpointFragments {
    pub fn port_forwarded_leader_endpoint(&self, leader_port: u16) -> Url {
        Url::parse(&format!(
            "http://127.0.0.1:{leader_port}{}",
            self.leader_endpoint_path
        ))
        .unwrap()
    }

    pub fn port_forwarded_endpoints(&self, leader_port: u16, helper_port: u16) -> (Url, Url) {
        (
            self.port_forwarded_leader_endpoint(leader_port),
            Url::parse(&format!(
                "http://127.0.0.1:{helper_port}{}",
                self.helper_endpoint_path
            ))
            .unwrap(),
        )
    }

    pub fn container_network_endpoints(&self) -> (Url, Url) {
        (
            Url::parse(&format!(
                "http://{}:8080{}",
                self.leader_endpoint_host, self.leader_endpoint_path
            ))
            .unwrap(),
            Url::parse(&format!(
                "http://{}:8080{}",
                self.helper_endpoint_host, self.helper_endpoint_path
            ))
            .unwrap(),
        )
    }
}
