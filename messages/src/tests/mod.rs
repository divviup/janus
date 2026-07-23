mod aggregation;
mod collection;
mod common;
mod hpke;
mod query;
mod task;
mod upload;

use crate::{
    BatchConfig, Duration, TaskConfiguration, TaskConfigurationBuilder, Time, TimePrecision, Url,
    VdafConfig,
};

/// A fixed [`TaskConfiguration`] reused by the AAD codec fixtures that embed one. Its encoding is
/// verified independently in [`task::roundtrip_task_configuration`], so the AAD fixtures can splice
/// in [`TASK_CONFIGURATION_HEX`] rather than recompute the whole config's bytes.
pub(crate) fn test_task_configuration() -> TaskConfiguration {
    let time_precision = TimePrecision::from_seconds(3600);
    TaskConfigurationBuilder::new(
        "foobar".as_bytes().to_vec(),
        Url::try_from("https://example.com/").unwrap(),
        Url::try_from("https://another.example.com/").unwrap(),
        time_precision,
        10000,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
    )
    .with_task_interval(
        Time::from_seconds_since_epoch(1000000, &time_precision),
        Duration::from_time_precision_units(28),
    )
    .unwrap()
    .build()
    .unwrap()
}

/// The wire encoding of [`test_task_configuration`], mirroring
/// [`task::roundtrip_task_configuration`].
pub(crate) const TASK_CONFIGURATION_HEX: &str = concat!(
    concat!(
        // task_info
        "06",           // length
        "666F6F626172"  // opaque data
    ),
    concat!(
        // leader_aggregator_url
        "0014",                                     // length
        "68747470733A2F2F6578616D706C652E636F6D2F"  // contents
    ),
    concat!(
        // helper_aggregator_url
        "001C",                                                     // length
        "68747470733A2F2F616E6F746865722E6578616D706C652E636F6D2F"  // contents
    ),
    "0000000000000E10", // time_precision
    "0000000000002710", // min_batch_size
    "01",               // batch_mode
    "0000",             // batch_config
    "00000001",         // vdaf_type
    "0000",             // vdaf_config
    concat!(
        // extensions (task_interval extension)
        "0014", // length
        concat!(
            "0001",             // extension_type (TaskInterval)
            "0010",             // extension_data length
            "0000000000000115", // start
            "000000000000001C", // duration
        ),
    ),
);
