terraform {
  backend "local" {}

  required_version = ">= 1.1.0"

  required_providers {
    kubernetes =  {
      source  = "hashicorp/kubernetes"
      version = "~> 2.8.0"
    }
  }
}

# We leave the Kubernetes provider block empty so that it can be configured using environment
# variables. See Terraform docs (1) for a list of supported variables.
# [1]: https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs#authentication
provider "kubernetes" {}

module "echo" {
  source = "../modules/echo_service"

  service_type = "ClusterIP"
}
