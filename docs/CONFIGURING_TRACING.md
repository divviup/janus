# OpenTelemetry Traces

Tracing spans from Janus components can be exported to distributed tracing
systems through the OpenTelemetry SDK, and various exporters.

Verbosity of traces can be controlled by setting the `RUST_TRACE` environment
variable to a [filter][EnvFilter], just as with `RUST_LOG` for log output. By
default, all spans and events of severity `INFO` or higher will be exported.

[EnvFilter]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/struct.EnvFilter.html

## Jaeger

[Jaeger](https://www.jaegertracing.io/) is a software stack that stores,
indexes, and displays distributed traces.

For local testing, start Jaeger by running
`docker run -d -e COLLECTOR_OTLP_ENABLED=true -p4317:4317 -p16686:16686 jaegertracing/all-in-one:latest`,
and open its web interface at http://localhost:16686/. Compile
`janus_aggregator` with the `otlp` feature enabled, to pull in the OTLP
exporter. Add the following configuration file stanza. Trace data will be pushed
to the local Jaeger agent via OTLP/gRPC.

```yaml
logging_config:
  open_telemetry_config:
    otlp:
      endpoint: "http://localhost:4317"
```

## Honeycomb

[Honeycomb](https://www.honeycomb.io/) is a Software-as-a-Service provider that
offers an integrated observability tool. To use it, sign up for an account,
create a team and environment, and retrieve the corresponding API key. Compile
`janus_aggregator` with the `otlp` feature enabled, to pull in the OTLP
exporter. Add the following section to the configuration file, subtituting in
the Honeycomb API key. Traces will be sent to Honeycomb via OTLP/gRPC.

```yaml
logging_config:
  open_telemetry_config:
    otlp:
      endpoint: "https://api.honeycomb.io:443"
      metadata:
        x-honeycomb-team: "YOUR_API_KEY"
```

The gRPC metadata can also be specified on the command line, with
`--otlp-tracing-metadata x-honeycomb-team=YOUR_API_KEY`, or through the
environment variable `OTLP_TRACING_METADATA`.
