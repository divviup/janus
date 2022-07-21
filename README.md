# janus
[![Build Status]][actions]

[Build Status]: https://github.com/divviup/janus/workflows/ci-build/badge.svg
[actions]: https://github.com/divviup/janus/actions?query=branch%3Amain

Janus is an experimental implementation of the
[Distributed Aggregation Protocol (DAP) specification](https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap).

It is currently in active development.

## Running janus\_server

The aggregator server requires a connection to a PostgreSQL 14 database. Prepare the database by executing the script at `db/schema.sql`. Most server configuration is done via a YAML file, following the structure documented on `janus_server::config::AggregatorConfig`. Record the database's connection URL, the address the aggregator server should listen on for incoming HTTP requests, and other settings in a YAML file, and pass the file's path on the command line as follows. (The database password can be passed through the command line or an environment variable rather than including it in the connection URL, see `aggregator --help`.)

```bash
aggregator --config-file <config-file> --role <role>
```

## Running tests

Tests require that [`docker`](https://www.docker.com) & [`kind`](https://kind.sigs.k8s.io) be installed on the machine running the tests and in the `PATH` of the test-runner's environment. The `docker` daemon must be running. CI tests currently use [`kind` 0.14.0](https://github.com/kubernetes-sigs/kind/releases/tag/v0.14.0) and the corresponding [Kubernetes 1.22 node image](kindest/node:v1.22.9@sha256:8135260b959dfe320206eb36b3aeda9cffcb262f4b44cda6b33f7bb73f453105) and using the same versions for local development is recommended.

To run janus tests, execute `cargo test`.

### inotify limits

If you experience issues with tests using Kind on Linux, you may need to adjust the `fs.inotify.max_user_instances` sysctl. Both systemd and Kubernetes inside each Kind cluster make use of inotify. When combined with other services and desktop applications, they may exhaust this per-user limit.

Check the sysctl with either of the following commands. On Ubuntu 20.04, it is set to 128 by default.

```bash
cat /proc/sys/fs/inotify/max_user_instances
sysctl fs.inotify.max_user_instances
```

To temporarily raise the limit, run `sudo sysctl -w fs.inotify.max_user_instances=512`. To permanently raise the limit, create or edit the file `/etc/sysctl.d/local.conf`, and insert `fs.inotify.max_user_instances=512`, then run `sudo service procps restart` to apply the configuration file immediately.

## Container image

To build a container image, run the following command.

```bash
DOCKER_BUILDKIT=1 docker build --tag=janus_server .
```

## Monitoring with `tokio-console`

Optional support is included to monitor the server's async runtime using `tokio-console`. When enabled, a separate tracing subscriber will be installed to monitor when the async runtime polls tasks, and expose that information to diagnostic tools via a gRPC server. Currently, this requires both changes to the aggregator configuration and to the build flags used at compilation. Add a stanza similar to the following to the configuration file.

```yaml
logging_config:
  tokio_console_config:
    enabled: true
    listen_address: 127.0.0.1:6669
```

Compile the server with the `tokio-console` feature enabled, and provide the flag `--cfg tokio_unstable` to `rustc`, as follows. (If `tokio-console` support is enabled in a build without the `tokio_unstable` flag, the server will panic upon startup)

```bash
RUSTFLAGS="--cfg tokio_unstable" CARGO_TARGET_DIR=target/tokio_unstable cargo build --features tokio-console
```

Install `tokio-console`, run the server, and run `tokio-console http://127.0.0.1:6669` to connect to it and monitor tasks.

## OpenTelemetry Traces

Tracing spans from the server can be exported to distributed tracing systems through the OpenTelemetry SDK, and various exporters.

### Jaeger

[Jaeger](https://www.jaegertracing.io/) is a software stack that stores, indexes, and displays distributed traces. While Jaeger supports the OpenTelemetry object model, it uses its own wire protocols, and thus requires Jaeger-specific exporters.

For local testing, start Jaeger by running `docker run -d -p6831:6831/udp -p6832:6832/udp -p16686:16686 -p14268:14268 jaegertracing/all-in-one:latest`, and open its web interface at http://localhost:16686/. Enable experimental support for Jaeger by compiling with the `jaeger` feature. Add the following configuration file stanza. Trace data will be pushed to the local Jaeger agent via UDP.

```yaml
logging_config:
  open_telemetry_config:
    jaeger:
```

### Honeycomb

[Honeycomb](https://www.honeycomb.io/) is a Software-as-a-Service provider that offers an integrated observability tool. To use it, sign up for an account, create a team and environment, and retrieve the corresponding API key. Compile `janus_server` with the `otlp` feature enabled, to pull in the OTLP exporter. Add the following section to the configuration file, subtituting in the Honeycomb API key. Traces will be sent to Honeycomb via OTLP/gRPC.

```yaml
logging_config:
  open_telemetry_config:
    otlp:
      endpoint: "https://api.honeycomb.io:443"
      metadata:
        x-honeycomb-team: "YOUR_API_KEY"
```

The gRPC metadata can also be specified on the command line, with `--otlp-tracing-metadata x-honeycomb-team=YOUR_API_KEY`, or through the environment variable `OTLP_TRACING_METADATA`.

## OpenTelemetry Metrics

Application-level metrics from the server can be exported to one of the following services.

### Prometheus

When the Prometheus exporter is enabled, a server will listen on port 9464 for metrics scrape requests. Prometheus must be configured to scrape the server, either manually or via an auto-discovery mechanism. Compile `janus_server` with the `prometheus` feature enabled, and add the following to the configuration file.
```yaml
metrics_config:
  exporter:
    prometheus:
      host: 0.0.0.0
      port: 9464
```

The IP address and port that Prometheus exporter listens on can optionally be set in the configuration file as above. If the `host` and `port` are not set, it will fall back to the environment variables `OTEL_EXPORTER_PROMETHEUS_HOST` and `OTEL_EXPORTER_PROMETHEUS_PORT`, or the default values of `0.0.0.0` and 9464.

### Honeycomb

Honeycomb also supports OpenTelemetry-formatted metrics, though only on the Enterprise and Pro plans. Compile `janus_server` with the `otlp` feature enabled, and add the following section to the configuration file. Note that the OTLP/gRPC exporter will push metrics at regular intervals.

```yaml
metrics_config:
  exporter:
    otlp:
      endpoint: "https://api.honeycomb.io:443"
      metadata:
        x-honeycomb-team: "YOUR_API_KEY"
        x-honeycomb-dataset: "YOUR_METRICS_DATASET"
```

The command line flag `--otlp-metrics-metadata` or environment variable `OTLP_METRICS_METADATA` may alternately be used to supply gRPC metadata for the metrics exporter.
