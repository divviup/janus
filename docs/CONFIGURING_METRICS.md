# OpenTelemetry Metrics

Application-level metrics from Janus components can be exported to one of the
following services.

## Prometheus

When the Prometheus exporter is enabled, a server will listen on port 9464 for
metrics scrape requests. Prometheus must be configured to scrape the server,
either manually or via an auto-discovery mechanism. Compile `janus_aggregator`
with the `prometheus` feature enabled, and add the following to the
configuration file.

```yaml
metrics_config:
  exporter:
    prometheus:
      host: 0.0.0.0
      port: 9464
```

The IP address and port that Prometheus exporter listens on can optionally be
set in the configuration file as above. If the `host` and `port` are not set, it
will fall back to the environment variables `OTEL_EXPORTER_PROMETHEUS_HOST` and
`OTEL_EXPORTER_PROMETHEUS_PORT`, or the default values of `0.0.0.0` and 9464.

## Honeycomb

Honeycomb also supports OpenTelemetry-formatted metrics, though only on the
Enterprise and Pro plans. Compile `janus_aggregator` with the `otlp` feature
enabled, add the following section to the configuration file, and provide your
Honeycomb API key through an environment variable of the form
`OTEL_EXPORTER_OTLP_HEADERS=x-honeycomb-team=YOUR_API_KEY,x-honeycomb-dataset=YOUR_METRICS_DATASET`.
Note that the OTLP/gRPC exporter will push metrics at regular intervals.

```yaml
metrics_config:
  exporter:
    otlp:
      endpoint: "https://api.honeycomb.io:443"
```
