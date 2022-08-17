//! Testing framework for functionality that interacts with Kubernetes.

use kube::config::{KubeConfigOptions, Kubeconfig};
use rand::{thread_rng, Rng};
use std::{
    io::{self, ErrorKind},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
use tempfile::NamedTempFile;
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};
use tracing::debug;

/// Cluster represents a running Kubernetes cluster.
pub struct Cluster {
    /// Path to the Kubernetes config file, e.g., `~/.kube/config`
    kubeconfig_path: PathBuf,
    /// Name of the `kubectl` context to use.
    context_name: String,
}

impl Cluster {
    /// Creates a handle to an existing Kubernetes cluster.
    pub fn new<P: AsRef<Path>>(kubeconfig_path: P, context_name: &str) -> Self {
        let kubeconfig_path = kubeconfig_path.as_ref();
        debug!(?kubeconfig_path, context_name, "Creating cluster handle");
        Self {
            kubeconfig_path: kubeconfig_path.to_path_buf(),
            context_name: context_name.to_owned(),
        }
    }

    /// Returns a new [`kube::Client`] configured to interact with this Kubernetes cluster.
    pub async fn client(&self) -> kube::Client {
        kube::Client::try_from(
            kube::Config::from_custom_kubeconfig(
                Kubeconfig::read_from(&self.kubeconfig_path).unwrap(),
                &KubeConfigOptions {
                    context: Some(self.context_name.clone()),
                    ..KubeConfigOptions::default()
                },
            )
            .await
            .unwrap(),
        )
        .unwrap()
    }

    /// Set up port forwarding from `local_port` to `service_port` on the service in the namespace.
    /// Returns a [`PortForwardGuard`] which will kill the child `kubectl` process on drop.
    pub async fn forward_port(
        &self,
        namespace: &str,
        service: &str,
        local_port: u16,
        service_port: u16,
    ) -> PortForward {
        let args = [
            "--kubeconfig",
            &self.kubeconfig_path.to_string_lossy(),
            "--context",
            &self.context_name,
            "--namespace",
            namespace,
            "port-forward",
            &format!("service/{service}"),
            &format!("{local_port}:{service_port}"),
        ];
        debug!(?args, "Invoking kubectl");
        let mut child = Command::new("kubectl")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        // Wait for up to five seconds for the forwarded port to be available.
        timeout(tokio::time::Duration::from_secs(5), async {
            loop {
                let stream = match TcpStream::connect(&format!("127.0.0.1:{local_port}")).await {
                    Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                        if let Ok(Some(status)) = child.try_wait() {
                            Err(io::Error::new(
                                ErrorKind::Other,
                                format!("child kubectl process exited with status {status})"),
                            ))
                        } else {
                            sleep(tokio::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                    r => r,
                }
                .unwrap();
                stream.writable().await.unwrap();
                debug!(local_port, service_port, "forwarded port became writable");
                break;
            }
        })
        .await
        .expect("timeout waiting for forwarded port to become writable");

        PortForward { child }
    }
}

/// EphemeralCluster represents a running ephemeral Kubernetes cluster for testing. Dropping an
/// EphemeralCluster will cause the associated Kubernetes cluster to be stopped & cleaned up.
pub struct EphemeralCluster {
    cluster: Cluster,
    kind_cluster_name: String,
}

impl EphemeralCluster {
    /// Creates & starts a new ephemeral Kubernetes cluster.
    pub fn create() -> Self {
        // Choose a temporary file location for our kube config.
        let kubeconfig_path = NamedTempFile::new().unwrap().into_temp_path().to_path_buf();

        // Choose a cluster name.
        let mut randomness = [0u8; 4];
        thread_rng().fill(&mut randomness);
        let kind_cluster_name = format!("janus-ephemeral-{}", hex::encode(&randomness));

        // Use kind to start the cluster, with the node image from kind v0.14.0 for Kubernetes 1.22,
        // matching current regular GKE release channel. This image version should be bumped in
        // lockstep with the version of kind installed by the ci-build workflow.
        // https://github.com/kubernetes-sigs/kind/releases/tag/v0.14.0
        // https://cloud.google.com/kubernetes-engine/docs/release-notes#regular-channel
        assert!(Command::new("kind")
            .args([
                "create",
                "cluster",
                "--kubeconfig",
                &kubeconfig_path.to_string_lossy(),
                "--name",
                &kind_cluster_name,
                "--image",
                "kindest/node:v1.22.9@sha256:8135260b959dfe320206eb36b3aeda9cffcb262f4b44cda6b33f7bb73f453105",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success());

        Self {
            // Kind prefixes the cluster name with "kind-" when creating a kubectl context
            cluster: Cluster::new(kubeconfig_path, &format!("kind-{kind_cluster_name}")),
            kind_cluster_name,
        }
    }

    pub fn cluster(&self) -> &Cluster {
        &self.cluster
    }
}

impl Drop for EphemeralCluster {
    fn drop(&mut self) {
        // Delete the cluster that was created when we created the EphemeralCluster.
        assert!(Command::new("kind")
            .args([
                "delete",
                "cluster",
                "--kubeconfig",
                &self.cluster.kubeconfig_path.to_string_lossy(),
                "--name",
                &self.kind_cluster_name,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success())
    }
}

/// A guard on a running `kubectl port-forward` process. The process will be killed and reaped when
/// the guard is dropped.
pub struct PortForward {
    child: Child,
}

impl Drop for PortForward {
    fn drop(&mut self) {
        debug!(?self.child, "dropping port forward");
        // We kill and reap child `kubectl` processes here to ensure that we don't orphan children
        // on test failures. This is normally a questionable practice, but acceptable since this is
        // only used in test code.
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::EphemeralCluster;
    use crate::test_util::install_test_trace_subscriber;
    use k8s_openapi::api::core::v1::Node;
    use kube::{api::ListParams, Api};

    #[tokio::test]
    async fn create_clusters() {
        // Create a couple of clusters, check communication, then drop them, to test that creating
        // multiple clusters does not lead to collisions in some namespace.

        install_test_trace_subscriber();

        let first_cluster = EphemeralCluster::create();
        let first_client = first_cluster.cluster.client().await;
        let first_nodes: Api<Node> = Api::all(first_client);
        assert_eq!(
            first_nodes
                .list(&ListParams::default())
                .await
                .iter()
                .count(),
            1
        );

        let second_cluster = EphemeralCluster::create();
        let second_client = second_cluster.cluster.client().await;
        let second_nodes: Api<Node> = Api::all(second_client);
        assert_eq!(
            second_nodes
                .list(&ListParams::default())
                .await
                .iter()
                .count(),
            1
        );
    }
}
