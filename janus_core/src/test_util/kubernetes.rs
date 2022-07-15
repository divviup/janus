//! Testing framework for functionality that interacts with Kubernetes.

use kube::config::KubeConfigOptions;
use rand::{thread_rng, Rng};
use std::process::{Command, Stdio};

/// EphemeralCluster represents a running ephemeral Kubernetes cluster for testing. Dropping an
/// EphemeralCluster will cause the associated Kubernetes cluster to be stopped & cleaned up.
pub struct EphemeralCluster {
    name: String,
}

impl EphemeralCluster {
    /// Creates & starts a new ephemeral Kubernetes cluster.
    pub fn create() -> Self {
        // Choose a cluster name.
        let mut randomness = [0u8; 4];
        thread_rng().fill(&mut randomness);
        let cluster_name = format!("janus-ephemeral-{}", hex::encode(&randomness));

        // Use kind to start the cluster.
        assert!(Command::new("kind")
            .args(["create", "cluster", "--name", &cluster_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());

        Self { name: cluster_name }
    }

    /// Returns a new [`kube::Client`] configured to interact with this Kubernetes cluster.
    pub async fn client(&self) -> kube::Client {
        kube::Client::try_from(
            kube::Config::from_kubeconfig(&KubeConfigOptions {
                context: Some(format!("kind-{}", self.name)),
                ..KubeConfigOptions::default()
            })
            .await
            .unwrap(),
        )
        .unwrap()
    }
}

impl Drop for EphemeralCluster {
    fn drop(&mut self) {
        // Delete the cluster that was created when we created the EphemeralCluster.
        assert!(Command::new("kind")
            .args(["delete", "cluster", "--name", &self.name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success())
    }
}
