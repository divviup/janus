# OpenTelemetry Traces

Tracing spans from Janus components can be exported to distributed tracing
systems through the OpenTelemetry SDK, and various exporters.

## Jaeger

[Jaeger](https://www.jaegertracing.io/) is a software stack that stores,
indexes, and displays distributed traces. While Jaeger supports the
OpenTelemetry object model, it uses its own wire protocols, and thus requires
Jaeger-specific exporters.

For local testing, start Jaeger by running `docker run -d -p6831:6831/udp
-p6832:6832/udp -p16686:16686 -p14268:14268 jaegertracing/all-in-one:latest`,
and open its web interface at http://localhost:16686/. Enable experimental
support for Jaeger by compiling with the `jaeger` feature. Add the following
configuration file stanza. Trace data will be pushed to the local Jaeger agent
via UDP.

```yaml
logging_config:
  open_telemetry_config: jaeger
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
