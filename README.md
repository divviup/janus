# janus

Janus is an experimental implementation of the
[Privacy Preserving Measurement (PPM) specification](https://github.com/abetterinternet/ppm-specification).

It is currently in active development.

## Running janus\_server

The aggregator server requires a connection to a PostgreSQL 14 database. Prepare the database by executing the script at `db/schema.sql`. Most server configuration is done via a YAML file, following the structure documented on `janus_server::config::AggregatorConfig`. Record the database's connection URL, the address the aggregator server should listen on for incoming HTTP requests, and other settings in a YAML file, and pass the file's path on the command line as follows. (The database password can be passed through the command line or an environment variable rather than including it in the connection URL, see `aggregator --help`.)

```bash
aggregator --config-file <config-file> --role <role>
```

## Running tests

To run janus tests, ensure docker is running locally and execute `cargo test`.

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

The gRPC metadata can also be specified on the command line, with `--otlp-metadata x-honeycomb-team=YOUR_API_KEY`.