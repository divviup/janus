use crate::metrics::{
    MetricsConfiguration, MetricsExporterConfiguration, OtlpExporterConfiguration,
};

#[test]
fn metrics_configuration_serde() {
    let config = yaml_serde::from_str::<MetricsConfiguration>("---").unwrap();
    assert_eq!(
        config,
        MetricsConfiguration {
            exporter: None,
            tokio: None
        }
    );

    let config = yaml_serde::from_str::<MetricsConfiguration>(
        "---
exporter:
  prometheus:
    host: 0.0.0.0
    port: 9464",
    )
    .unwrap();
    assert_eq!(
        config,
        MetricsConfiguration {
            exporter: Some(MetricsExporterConfiguration::Prometheus {
                host: Some("0.0.0.0".into()),
                port: Some(9464),
            }),
            tokio: None,
        }
    );

    let config = yaml_serde::from_str::<MetricsConfiguration>(
        "---
exporter:
  otlp:
    endpoint: https://example.com/",
    )
    .unwrap();
    assert_eq!(
        config,
        MetricsConfiguration {
            exporter: Some(MetricsExporterConfiguration::Otlp(
                OtlpExporterConfiguration {
                    endpoint: "https://example.com/".into()
                }
            )),
            tokio: None
        }
    );
}
