# janus
[![Build Status]][actions]

[Build Status]: https://github.com/divviup/janus/workflows/ci-build/badge.svg
[actions]: https://github.com/divviup/janus/actions?query=branch%3Amain

Janus is an experimental implementation of the [Distributed Aggregation Protocol
(DAP) specification](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/).
Currently it supports VDAFs with trivial aggregation parameters only, e.g.
Prio3. VDAFs with nontrivial aggregation parameters (e.g. Poplar1) are not yet
supported.

Janus is currently in active development.

## Draft versions and release branches

The `main` branch is under continuous development and will usually be partway
between DAP drafts. Janus uses stable release branches to maintain
implementations of different DAP draft versions. Rust crates and container
images with versions `x.y.z` are released from a corresponding `release/x.y`
branch.

| Git branch | Draft version | Conforms to protocol? | Status |
| ---------- | ------------- | --------------------- | ------ |
| `release/0.1` | [`draft-ietf-ppm-dap-01`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/01/) | Yes | Unmaintained as of December 7, 2022 |
| `release/0.2` | [`draft-ietf-ppm-dap-02`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/02/) | Yes | Unmaintained as of July 13, 2023 |
| `release/0.3` | [`draft-ietf-ppm-dap-03`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/03/) | Yes | Unmaintained as of February 6, 2023 |
| `release/0.subscriber-01` | [`draft-ietf-ppm-dap-02`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/02/) plus extensions | No | Supported |
| `main` | [`draft-ietf-ppm-dap-04`](https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/04/) | Yes | Supported |

## Building

[`docker`](https://www.docker.com) must be installed at build time, and the
`docker` daemon must be running. To build Janus, execute `cargo build`.

Note that `podman` is not an acceptable substitute for `docker`. There are
subtle incompatibilities between the two that will cause tests to fail.

### Container image

To build container images, run `docker buildx bake --load`. This will produce images
tagged `janus_aggregator`, `janus_aggregation_job_creator`,
`janus_aggregation_job_driver`, `janus_collection_job_driver`, `janus_cli`,
`janus_interop_client`, `janus_interop_aggregator`, and
`janus_interop_collector` by default.

Pre-built container images are available at
[us-west2-docker.pkg.dev/divviup-artifacts-public/janus](https://us-west2-docker.pkg.dev/divviup-artifacts-public/janus).

## Running tests

Tests require that [`docker`](https://www.docker.com) and
[`kind`](https://kind.sigs.k8s.io) be installed on the machine running the tests
and in the `PATH` of the test-runner's environment. The `docker` daemon must be
running. CI tests currently use [`kind`
0.17.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.17.0) and the
corresponding Kubernetes 1.24 node image
(kindest/node:v1.24.7@sha256:577c630ce8e509131eab1aea12c022190978dd2f745aac5eb1fe65c0807eb315).
Using the same versions for local development is recommended.

To run Janus tests, execute `cargo test`.

### inotify limits

If you experience issues with tests using Kind on Linux, you may need to [adjust
inotify
sysctls](https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files).
Both systemd and Kubernetes inside each Kind node make use of inotify. When
combined with other services and desktop applications, they may exhaust per-user
limits.

## Deploying Janus

See the [documentation on deploying Janus](docs/DEPLOYING.md) for details about
its configuration and operation.

## Cargo features

`janus_core` has the following features available.

* `database`: Enables implementations of `postgres_types::ToSql` and
  `postgres_types::FromSql` on `janus_core::Interval`.
* `test-util`: Enables miscellaneous test-only APIs. This should not be used
  outside of tests, and any such APIs do not carry any stability guarantees.

`janus_aggregator` has the following features available.

* `otlp`: Enables OTLP exporter support for both metrics and tracing. See the
  [metrics](docs/CONFIGURING_METRICS.md) and
  [tracing](docs/CONFIGURING_TRACING.md) documentation for configuration
  instructions.
* `prometheus`: Enables a Prometheus metrics exporter; see the
  [documentation](docs/CONFIGURING_METRICS.md) for configuration instructions.
* `test-util`: Enables miscellaneous test-only APIs. This should not be used
  outside of tests, and any such APIs do not carry any stability guarantees.
* `tokio-console`: Enables a tracing subscriber and server to support
  [`tokio-console`](https://github.com/tokio-rs/console). See the
  [documentation](docs/CONFIGURING_TOKIO_CONSOLE.md) for configuration
  instructions.
