# janus

Janus is an experimental implementation of the
[Privacy Preserving Measurement (PPM) specification](https://github.com/abetterinternet/ppm-specification).

It is currently in active development.

## Running janus\_server

The aggregator server requires a connection to a PostgreSQL 14 database. Prepare the database by executing the script at `db/schema.sql`. Most server configuration is done via a YAML file, following the structure documented on `janus_server::config::AggregatorConfig`. Record the database's connection URL, the address the aggregator server should listen on for incoming HTTP requests, and other settings in a YAML file, and pass the file's path on the command line as follows. (The database password can be passed through the command line or an environment variable rather than including it in the connection URL, see `aggregator --help`.)

```bash
aggregator --config-file <config-file> --role <role>
```

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

## OpenTelemetry with Jaeger

There is experimental support for exporting application traces to [Jaeger](https://www.jaegertracing.io/). Jaeger is an OpenTelemetry-compliant software stack that stores, indexes, and displays distributed traces. When enabled, tracing spans will be mapped to OpenTelemetry spans, and trace data will be published to a local Jaeger agent via UDP (in Jaeger's Thrift-encoded protocol). Enable this feature by compiling with the `jaeger` feature enabled, and add the following to the configuration file.

```yaml
logging_config:
  otel_jaeger: true
```

For local development, run a containerized Jaeger deployment with the following command, and open its web interface at http://localhost:16686/.

```bash
docker run -d -p6831:6831/udp -p6832:6832/udp -p16686:16686 -p14268:14268 jaegertracing/all-in-one:latest
```
