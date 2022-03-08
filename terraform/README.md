# Janus Terraform module

We use these Terraform modules to manage deployments of Janus to cloud and local dev environments. We provide a distinct main module for each so that we can use different [Terraform backends](https://www.terraform.io/language/settings/backends) and configure other modules separately.

A Janus environment `foo` is defined by a file `variables/foo.tfvars` which contains configuration for that environment. Among other behaviors, the variables files specify whether the environment is deployed to Google Kubernetes Engine (GKE) or to a local `kind` cluster. To see what Terraform wants to do to environment foo, run:

    ENV=foo make plan

To apply those changes, run:

    ENV=foo make apply

You may need additional environment variables or other context to interact with an environment via Terraform. See [Authentication for Terraform](https://github.com/abetterinternet/isrg-cloud-bootstrap#authentication-for-terraform) for details, as well as the sections below relevant to the environment you are working with.

## Google Kubernetes Engine

Staging and production environments of Janus are deployed into [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine). This uses `main_gcp/main.tf`. Variables files for GKE environments should include the variable `state_bucket`, whose value should be the name of a GCS bucket to use with the [`gcs` Terraform backend](https://www.terraform.io/language/settings/backends/gcs).

[TODO: adapt prio-server/cluster-bootstrap to bringup a GKE cluster for Janus and document how to do that here]

## Local development with Kind

To enable local development and testing in CI, we use [`kind`](https://kind.sigs.k8s.io/) (Kubernetes IN Docker). Kind uses Docker containers to run a single-node Kubernetes control plane and optionally additional worker nodes. This uses `main_local/main.tf`. Variables files for local environments may include the `tfstate_path` variable, whose value is used as the `path` value in the [`local` Terraform backend](https://www.terraform.io/language/settings/backends/local).

You will need the `kind` to manage clusters. See [the `kind` documentation](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) for instructions on installing. The quick start guide also has instructions on [creating a cluster](https://kind.sigs.k8s.io/docs/user/quick-start/#creating-a-cluster). By default `kind` creates a cluster where a single node hosts both the control plane and workers. If you want to create a more complex cluster topology, you can use a configuration file like this:

    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    name: test-cluster
    nodes:
      - role: control-plane
        labels:
          topology.kubernetes.io/zone: control-plane
      - role: worker
        labels:
          topology.kubernetes.io/zone: workers-1
      - role: worker
        labels:
          topology.kubernetes.io/zone: workers-2

In this example, we apply `topology.kubernetes.io/zone` labels to each worker node which could later be used as [pod scheduling constraints](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/).

`kind` supports rootless containers with either Docker or Podman. Follow [their instructions on setup](https://kind.sigs.k8s.io/docs/user/rootless/).

### Deploying into a `kind` cluster

While we don't currently use Terraform to provision `kind` clusters, we do use Terraform to deploy resources into the cluster, just like in the cloud. Setting up your cluster with `kind cluster create` should have populated a [`kubectl` context](https://kubernetes.io/docs/reference/kubectl/cheatsheet/#kubectl-context-and-configuration) with appropriate credentials to administer your cluster. You can use any number of [environment variables](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs#argument-reference) to configure the Terraform Kubernetes provider to use that context. For example, supposing that you had a context `kind-cluster` in your `kubectl` config file at `~/.kube/config`, you might use it with environment `local-dev` thusly:

    KUBE_CTX=kind-cluster KUBE_CONFIG_PATH=~/.kube/config ENV=local-dev make apply

### Networking and ingress into the cluster

`kind` creates a [Docker network](https://docs.docker.com/network/#network-drivers) of type `kind` that implements the Kubernetes network model. In local development environments, we use a [Kubernetes service](https://kubernetes.io/docs/concepts/services-networking/service/) with [`ServiceType`](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer) `ClusterIP`. This means that the service is visible within the Kubernetes cluster, but not externally to the host. If we want to run integration tests that exercise Janus API endpoints from outside the cluster, we use [`kubectl port-forward`](https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/) to expose a `ClusterIP`. For instance, suppose you have a service named `echo` in namespace `echospace` which listens on port `5678`, you would run (on the host):

    kubectl -n echospace port-forward service/echo 8080:5678

Or whatever _host_ port you want instead of `8080`. Other processes may now communicate with `localhost:8080` or `127.0.0.1:8080` or even `[::1]:8080` and traffic will be routed to the `echo` service in namespace `echospace`.

#### On `ServiceType=LoadBalancer` in `kind`

`kind` does support `LoadBalancer` services via [Metallb](https://kind.sigs.k8s.io/docs/user/loadbalancer/). However, the resulting LB gets an IP on the `kind` Docker network, which is not routable from the host network by default. While the two could be bridged, it seems more straightforward to use `kubectl port-forward` to expose a `ClusterIP`.
