variable "service_type" {
  type        = string
  description = <<DESCRIPTION
The Kubernetes ServiceType to use when creating a service. Must be one of the
types documented in https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types
DESCRIPTION
}

resource "kubernetes_namespace_v1" "echo" {
  metadata {
    name = "echo"
  }
}

resource "kubernetes_service_account_v1" "echo" {
  automount_service_account_token = false
  metadata {
    name      = "echo"
    namespace = kubernetes_namespace_v1.echo.metadata[0].name
  }
}

resource "kubernetes_service_v1" "echo" {
  metadata {
    name      = "echo"
    namespace = kubernetes_namespace_v1.echo.metadata[0].name
  }
  spec {
    port {
      port     = 5678
      protocol = "TCP"
    }
    type = var.service_type
    # Selector must match the label(s) on kubernetes_deployment.echo
    selector = {
      app = "echo"
    }
  }
}

resource "kubernetes_deployment_v1" "echo" {
  metadata {
    name      = "echo"
    namespace = kubernetes_namespace_v1.echo.metadata[0].name
  }
  spec {
    selector {
      match_labels = {
        app = "echo"
      }
    }
    template {
      metadata {
        labels = {
          app = "echo"
        }
      }
      spec {
        service_account_name = kubernetes_service_account_v1.echo.metadata[0].name
        container {
          name  = "echo"
          image = "hashicorp/http-echo:0.2.3"
          args  = ["-text=hello"]
          port {
            container_port = 5678
            protocol       = "TCP"
          }
        }
      }
    }
  }
}
