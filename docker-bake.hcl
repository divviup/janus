variable "GIT_REVISION" {
  default = "unknown"
}

variable "VERSION" {
  default = "latest"
}

variable "SQLX_VERSION" {
  default = "0.7.2"
}

variable "GITHUB_REF_NAME" {}

variable "GITHUB_BASE_REF" {}

group "default" {
  targets = ["janus", "interop_binaries"]
}

group "janus" {
  targets = [
    "janus_aggregator",
    "janus_aggregation_job_creator",
    "janus_aggregation_job_driver",
    "janus_collection_job_driver",
    "janus_cli",
    "janus_db_migrator",
  ]
}

group "interop_binaries" {
  targets = [
    "janus_interop_client",
    "janus_interop_aggregator",
    "janus_interop_collector",
  ]
}

group "release" {
  targets = ["janus_release", "interop_binaries_release"]
}

group "janus_release" {
  targets = [
    "janus_aggregator_release",
    "janus_aggregation_job_creator_release",
    "janus_aggregation_job_driver_release",
    "janus_collection_job_driver_release",
    "janus_cli_release",
    "janus_db_migrator_release",
  ]
}

group "interop_binaries_release" {
  targets = [
    "janus_interop_client_release",
    "janus_interop_aggregator_release",
    "janus_interop_collector_release",
  ]
}

group "interop_binaries_small" {
  targets = [
    "janus_interop_client_small",
    "janus_interop_aggregator_small",
    "janus_interop_collector_small",
  ]
}

target "janus_aggregator" {
  args = {
    GIT_REVISION = "${GIT_REVISION}"
  }
  cache-from = [
    "type=gha,scope=main-janus",
    "type=gha,scope=${GITHUB_BASE_REF}-janus",
    "type=gha,scope=${GITHUB_REF_NAME}-janus",
  ]
  cache-to = ["type=gha,scope=${GITHUB_REF_NAME}-janus,mode=max"]
  tags     = ["janus_aggregator:${VERSION}"]
}

target "janus_aggregator_release" {
  inherits = ["janus_aggregator"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_aggregator:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_aggregator:${VERSION}",
  ]
}

target "janus_aggregation_job_creator" {
  args = {
    BINARY       = "aggregation_job_creator"
    GIT_REVISION = "${GIT_REVISION}"
  }
  cache-from = [
    "type=gha,scope=main-janus",
    "type=gha,scope=${GITHUB_BASE_REF}-janus",
    "type=gha,scope=${GITHUB_REF_NAME}-janus",
  ]
  tags = ["janus_aggregation_job_creator:${VERSION}"]
}

target "janus_aggregation_job_creator_release" {
  inherits = ["janus_aggregation_job_creator"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_aggregation_job_creator:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_aggregation_job_creator:${VERSION}",
  ]
}

target "janus_aggregation_job_driver" {
  args = {
    BINARY       = "aggregation_job_driver"
    GIT_REVISION = "${GIT_REVISION}"
  }
  cache-from = [
    "type=gha,scope=main-janus",
    "type=gha,scope=${GITHUB_BASE_REF}-janus",
    "type=gha,scope=${GITHUB_REF_NAME}-janus",
  ]
  tags = ["janus_aggregation_job_driver:${VERSION}"]
}

target "janus_aggregation_job_driver_release" {
  inherits = ["janus_aggregation_job_driver"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_aggregation_job_driver:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_aggregation_job_driver:${VERSION}",
  ]
}

target "janus_collection_job_driver" {
  args = {
    BINARY       = "collection_job_driver"
    GIT_REVISION = "${GIT_REVISION}"
  }
  cache-from = [
    "type=gha,scope=main-janus",
    "type=gha,scope=${GITHUB_BASE_REF}-janus",
    "type=gha,scope=${GITHUB_REF_NAME}-janus",
  ]
  tags = ["janus_collection_job_driver:${VERSION}"]
}

target "janus_collection_job_driver_release" {
  inherits = ["janus_collection_job_driver"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_collection_job_driver:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_collection_job_driver:${VERSION}",
  ]
}

target "janus_cli" {
  args = {
    BINARY       = "janus_cli"
    GIT_REVISION = "${GIT_REVISION}"
  }
  cache-from = [
    "type=gha,scope=main-janus",
    "type=gha,scope=${GITHUB_BASE_REF}-janus",
    "type=gha,scope=${GITHUB_REF_NAME}-janus",
  ]
  tags = ["janus_cli:${VERSION}"]
}

target "janus_cli_release" {
  inherits = ["janus_cli"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_cli:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_cli:${VERSION}",
  ]
}

target "janus_db_migrator" {
  args = {
    GIT_REVISION = "${GIT_REVISION}"
    SQLX_VERSION = "${SQLX_VERSION}"
  }
  dockerfile = "Dockerfile.sqlx"
  cache-from = [
    "type=gha,scope=main-janus",
    "type=gha,scope=${GITHUB_BASE_REF}-janus",
    "type=gha,scope=${GITHUB_REF_NAME}-janus",
  ]
  tags = ["janus_db_migrator:${VERSION}"]
}

target "janus_db_migrator_release" {
  inherits = ["janus_db_migrator"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_db_migrator:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_db_migrator:${VERSION}",
  ]
}

target "janus_interop_client" {
  args = {
    BINARY = "janus_interop_client"
  }
  dockerfile = "Dockerfile.interop"
  cache-from = [
    "type=gha,scope=main-interop",
    "type=gha,scope=${GITHUB_BASE_REF}-interop",
    "type=gha,scope=${GITHUB_REF_NAME}-interop",
  ]
  tags = ["janus_interop_client:${VERSION}"]
}

target "janus_interop_client_release" {
  inherits = ["janus_interop_client"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_interop_client:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_interop_client:${VERSION}",
  ]
}

target "janus_interop_aggregator" {
  dockerfile = "Dockerfile.interop_aggregator"
  cache-from = [
    "type=gha,scope=main-interop",
    "type=gha,scope=${GITHUB_BASE_REF}-interop",
    "type=gha,scope=${GITHUB_REF_NAME}-interop",
  ]
  cache-to = ["type=gha,scope=${GITHUB_REF_NAME}-interop,mode=max"]
  tags     = ["janus_interop_aggregator:${VERSION}"]
}

target "janus_interop_aggregator_release" {
  inherits = ["janus_interop_aggregator"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_interop_aggregator:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_interop_aggregator:${VERSION}",
  ]
}

target "janus_interop_collector" {
  args = {
    BINARY = "janus_interop_collector"
  }
  dockerfile = "Dockerfile.interop"
  cache-from = [
    "type=gha,scope=main-interop",
    "type=gha,scope=${GITHUB_BASE_REF}-interop",
    "type=gha,scope=${GITHUB_REF_NAME}-interop",
  ]
  tags = ["janus_interop_collector:${VERSION}"]
}

target "janus_interop_collector_release" {
  inherits = ["janus_interop_collector"]
  tags = [
    "us-west2-docker.pkg.dev/janus-artifacts/janus/janus_interop_collector:${VERSION}",
    "us-west2-docker.pkg.dev/divviup-artifacts-public/janus/janus_interop_collector:${VERSION}",
  ]
}

# These targets should match the `docker build` commands run in the
# janus_interop_binaries build script. They are run separately in CI for
# caching purposes.

target "janus_interop_client_small" {
  args = {
    PROFILE = "small"
    BINARY  = "janus_interop_client"
  }
  cache-from = [
    "type=gha,scope=main-interop-small",
    "type=gha,scope=${GITHUB_BASE_REF}-interop-small",
    "type=gha,scope=${GITHUB_REF_NAME}-interop-small",
  ]
  dockerfile = "Dockerfile.interop"
}

target "janus_interop_aggregator_small" {
  args = {
    PROFILE = "small"
  }
  cache-from = [
    "type=gha,scope=main-interop-small",
    "type=gha,scope=${GITHUB_BASE_REF}-interop-small",
    "type=gha,scope=${GITHUB_REF_NAME}-interop-small",
  ]
  cache-to   = ["type=gha,scope=${GITHUB_REF_NAME}-interop-small,mode=max"]
  dockerfile = "Dockerfile.interop_aggregator"
}

target "janus_interop_collector_small" {
  args = {
    PROFILE = "small"
    BINARY  = "janus_interop_collector"
  }
  cache-from = [
    "type=gha,scope=main-interop-small",
    "type=gha,scope=${GITHUB_BASE_REF}-interop-small",
    "type=gha,scope=${GITHUB_REF_NAME}-interop-small",
  ]
  dockerfile = "Dockerfile.interop"
}
