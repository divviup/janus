//! Testing framework for functionality that interacts with Kubernetes.

use anyhow::Context;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{
    api::ListParams,
    config::{KubeConfigOptions, Kubeconfig},
    Api, ResourceExt,
};
use rand::random;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use stopper::Stopper;
use tempfile::NamedTempFile;
use tokio::{
    net::{TcpListener, TcpStream},
    task::{self},
};
use tokio_stream::wrappers::TcpListenerStream;
use tracing::{debug, error, trace};

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

    /// Set up port forwarding from a dynamically chosen local port to `service_port` on the service
    /// in the namespace. Returns a [`PortForward`] handle.
    pub async fn forward_port(
        &self,
        namespace: &str,
        service_name: &str,
        service_port: u16,
    ) -> PortForward {
        // Fetch the service.
        let client = self.client().await;
        let services: Api<Service> = Api::namespaced(client, namespace);
        let service = services.get(service_name).await.unwrap();
        let selector = service.spec.as_ref().unwrap().selector.as_ref().unwrap();

        // List pods that match the label key-value pairs in the service's selector. Pick the first
        // one.
        let mut label_selector_param = String::with_capacity(
            selector
                .iter()
                .map(|(name, value)| name.len() + value.len() + 2)
                .sum(),
        );
        for (name, value) in selector.iter() {
            label_selector_param.push_str(name);
            label_selector_param.push('=');
            label_selector_param.push_str(value);
            label_selector_param.push(',');
        }
        label_selector_param.pop();
        let lp = ListParams::default().labels(&label_selector_param);
        let client = self.client().await;
        let pods: Api<Pod> = Api::namespaced(client, namespace);
        let matching_pods = pods.list(&lp).await.unwrap();
        let pod = matching_pods
            .items
            .get(0)
            .unwrap_or_else(|| panic!("could not find any pods for the service {service_name}"));
        let pod_name = pod.name_unchecked();

        // Set up a port forwarding connection with the pod. (based on the pod_portforward_bind
        // example from the kube crate)
        let tcp_listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let local_port = tcp_listener.local_addr().unwrap().port();
        debug!(
            namespace,
            service_name, service_port, local_port, "Forwarding port"
        );
        let stopper = Stopper::new();
        let stream = stopper.stop_stream(TcpListenerStream::new(tcp_listener));
        task::spawn({
            let stopper = stopper.clone();
            async move {
                let res = stream
                    .try_for_each(|stream| async {
                        let (pods, pod_name, stopper) =
                            (pods.clone(), pod_name.clone(), stopper.clone());
                        trace!(local_port, "new connection");
                        task::spawn(async move {
                            if let Err(e) =
                                forward_connection(&pods, &pod_name, service_port, stream, &stopper)
                                    .await
                            {
                                error!(local_port, error = %e, "Port forward error");
                            }
                        });
                        Ok(())
                    })
                    .await;
                if let Err(e) = res {
                    error!(local_port, error = %e, "Port forward TCP server error");
                }
            }
        });

        // Listen on a local TCP port, and forward incoming connections over the port forwarding
        // connection.

        PortForward {
            local_port,
            stopper,
        }
    }
}

async fn forward_connection(
    pods_api: &Api<Pod>,
    pod_name: &str,
    port: u16,
    mut tcp_stream: TcpStream,
    stopper: &Stopper,
) -> anyhow::Result<()> {
    let mut forwarder = pods_api.portforward(pod_name, &[port]).await?;
    let mut pod_stream = forwarder
        .take_stream(port)
        .context("stream for forwarded port was missing")?;
    stopper
        .stop_future(tokio::io::copy_bidirectional(
            &mut tcp_stream,
            &mut pod_stream,
        ))
        .await
        .transpose()?;
    drop(pod_stream);
    forwarder.join().await?;
    trace!("connection closed");
    Ok(())
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
        let kind_cluster_name = format!("janus-ephemeral-{}", hex::encode(random::<[u8; 4]>()));

        // Use kind to start the cluster, with the node image from kind v0.17.0 for Kubernetes 1.24,
        // matching current regular GKE release channel. This image version should be bumped in
        // lockstep with the version of kind installed by the ci-build workflow.
        // https://github.com/kubernetes-sigs/kind/releases/tag/v0.17.0
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
                "kindest/node:v1.24.7@sha256:\
                 577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315",
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

/// An active port forward into a Kubernetes cluster. The forwarded port will be closed when this
/// value is dropped.
pub struct PortForward {
    local_port: u16,
    stopper: Stopper,
}

impl PortForward {
    /// Returns the local port being forwarded into a Kubernetes cluster.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        debug!(?self.local_port, "dropping port forward");
        self.stopper.stop();
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
