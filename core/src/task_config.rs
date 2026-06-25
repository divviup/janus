//! Construction of canonical [`TaskConfiguration`] messages from a task's internal parameters.
//!
//! In DAP-18, the task's [`TaskConfiguration`] is bound into the HPKE additional authenticated data
//! (AAD) for input shares and aggregate shares. Every party (both aggregators, the client, and the
//! collector) must independently reconstruct *byte-identical* [`TaskConfiguration`] bytes, or all
//! decryption fails. [`build_task_configuration`] is the single canonical construction path, so
//! that normalization (e.g. of aggregator endpoint URLs) and the mapping of internal
//! representations onto the wire format happen in exactly one place.

use janus_messages::{
    BatchConfig, Error, Interval, TaskConfiguration, TaskExtension, TimePrecision, Url as DapUrl,
    VdafConfig,
};
use url::Url;

use crate::url_ensure_trailing_slash;

/// Construct a canonical [`TaskConfiguration`] from a task's parameters, normalizing the inputs so
/// that every party reconstructs byte-identical bytes.
#[allow(clippy::too_many_arguments)]
pub fn build_task_configuration(
    task_info: Vec<u8>,
    leader_aggregator_endpoint: Url,
    helper_aggregator_endpoint: Url,
    time_precision: TimePrecision,
    min_batch_size: u64,
    batch_config: BatchConfig,
    vdaf_config: VdafConfig,
    task_interval: Option<Interval>,
) -> Result<TaskConfiguration, Error> {
    let leader_aggregator_endpoint = normalize_endpoint(leader_aggregator_endpoint)?;
    let helper_aggregator_endpoint = normalize_endpoint(helper_aggregator_endpoint)?;

    // The optional task_interval becomes the lone extension, or none.
    let extensions = Vec::from_iter(task_interval.map(TaskExtension::TaskInterval));

    TaskConfiguration::new(
        task_info,
        leader_aggregator_endpoint,
        helper_aggregator_endpoint,
        time_precision,
        min_batch_size,
        batch_config,
        vdaf_config,
        extensions,
    )
}

/// Normalize an aggregator endpoint and convert it to the DAP wire [`DapUrl`] representation.
fn normalize_endpoint(endpoint: Url) -> Result<DapUrl, Error> {
    let endpoint = url_ensure_trailing_slash(endpoint);
    DapUrl::try_from(endpoint.as_str().as_bytes())
        .map_err(|_| Error::InvalidParameter("aggregator endpoint is not a valid DAP URL"))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use janus_messages::{BatchConfig, Duration, Error, Interval, Time, TimePrecision, VdafConfig};
    use prio::codec::Encode as _;
    use url::Url;

    use super::build_task_configuration;

    fn leader() -> Url {
        Url::parse("https://leader.example.com").unwrap()
    }

    fn helper() -> Url {
        Url::parse("https://helper.example.com").unwrap()
    }

    #[test]
    fn normalizes_endpoints() {
        // Neither input URL ends with a slash; the synthesized configuration must.
        let config = build_task_configuration(
            b"task".to_vec(),
            leader(),
            helper(),
            TimePrecision::from_seconds(3600),
            100,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            None,
        )
        .unwrap();
        assert_eq!(
            config.leader_aggregator_endpoint().to_string(),
            "https://leader.example.com/"
        );
        assert_eq!(
            config.helper_aggregator_endpoint().to_string(),
            "https://helper.example.com/"
        );
    }

    #[test]
    fn no_task_interval() {
        let config = build_task_configuration(
            b"task".to_vec(),
            leader(),
            helper(),
            TimePrecision::from_seconds(3600),
            100,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            None,
        )
        .unwrap();
        assert!(config.extensions().is_empty());
        assert_eq!(config.task_interval(), None);
    }

    #[test]
    fn carries_task_interval() {
        let interval = Interval::new(
            Time::from_time_precision_units(1000),
            Duration::from_time_precision_units(28),
        )
        .unwrap();
        let config = build_task_configuration(
            b"task".to_vec(),
            leader(),
            helper(),
            TimePrecision::from_seconds(3600),
            100,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            Some(interval),
        )
        .unwrap();
        assert_eq!(config.task_interval(), Some(interval));
    }

    #[test]
    fn rejects_empty_task_info() {
        assert_matches!(
            build_task_configuration(
                Vec::new(),
                leader(),
                helper(),
                TimePrecision::from_seconds(3600),
                100,
                BatchConfig::TimeInterval,
                VdafConfig::Prio3Count,
                None,
            ),
            Err(Error::InvalidParameter(_))
        );
    }

    /// Pins the exact encoded bytes produced by the canonical builder. Because taskprov clients can
    /// be non-Janus, this synthesized encoding is a cross-implementation wire-compatibility
    /// contract, so we assert the bytes directly rather than only round-tripping.
    #[test]
    fn encoded_test_vector() {
        let time_precision = TimePrecision::from_seconds(3600);
        let config = build_task_configuration(
            b"foobar".to_vec(),
            Url::parse("https://example.com").unwrap(),
            Url::parse("https://another.example.com").unwrap(),
            time_precision,
            10000,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            Some(
                Interval::new(
                    Time::from_time_precision_units(1000000),
                    Duration::from_time_precision_units(28),
                )
                .unwrap(),
            ),
        )
        .unwrap();

        assert_eq!(
            hex::encode(config.get_encoded().unwrap()),
            concat!(
                // task_info: length 0x06, "foobar"
                "06",
                "666f6f626172",
                // leader_aggregator_endpoint: length 0x0014, "https://example.com/"
                "0014",
                "68747470733a2f2f6578616d706c652e636f6d2f",
                // helper_aggregator_endpoint: length 0x001c, "https://another.example.com/"
                "001c",
                "68747470733a2f2f616e6f746865722e6578616d706c652e636f6d2f",
                // time_precision: 3600
                "0000000000000e10",
                // min_batch_size: 10000
                "0000000000002710",
                // batch_config: TimeInterval (mode 0x01, empty config)
                "01",
                "0000",
                // vdaf_config: Prio3Count (type 0x00000001, empty config)
                "00000001",
                "0000",
                // extensions: u16 length prefix, then one task_interval extension
                "0014",
                // extension_type: task_interval (0x0001)
                "0001",
                // extension_data: u16 length 0x10, Interval{start: 1000000, duration: 28}
                "0010",
                "00000000000f4240",
                "000000000000001c",
            )
        );
    }
}
