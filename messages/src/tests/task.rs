use std::collections::HashSet;

use assert_matches::assert_matches;
use prio::codec::{CodecError, Decode as _, Encode as _};

use crate::{
    BatchConfig, Duration, Interval, TaskConfiguration, TaskConfigurationBuilder, TaskExtension,
    TaskExtensionType, Time, TimePrecision, Url, VdafConfig, roundtrip_encoding,
};

#[test]
fn roundtrip_task_configuration() {
    let time_precision = TimePrecision::from_seconds(3600);
    roundtrip_encoding(&[
        (
            TaskConfigurationBuilder::new(
                "foobar".as_bytes().to_vec(),
                Url::try_from("https://example.com/".as_ref()).unwrap(),
                Url::try_from("https://another.example.com/".as_ref()).unwrap(),
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
            .unwrap(),
            concat!(
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
                "0000000000002710", // min_batch_size (u64)
                "01",               // batch_mode
                concat!(
                    // batch_config
                    "0000", // length
                ),
                "00000001", // vdaf_type
                concat!(
                    // vdaf_config
                    "0000", // length
                ),
                concat!(
                    // extensions (task_interval extension)
                    "0014", // length (20 bytes)
                    concat!(
                        "0001",             // extension_type (TaskInterval)
                        "0010",             // extension_data length (16 bytes)
                        "0000000000000115", // start (277 time precision units)
                        "000000000000001C", // duration (28 time precision units)
                    ),
                ),
            ),
        ),
        (
            TaskConfigurationBuilder::new(
                "f".as_bytes().to_vec(),
                Url::try_from("https://example.com/".as_ref()).unwrap(),
                Url::try_from("https://another.example.com/".as_ref()).unwrap(),
                TimePrecision::from_seconds(1000),
                1000,
                BatchConfig::LeaderSelected,
                VdafConfig::Prio3Sum {
                    max_measurement: 0xFF,
                },
            )
            .with_extensions(Vec::from([TaskExtension::Unknown {
                extension_type: TaskExtensionType::Reserved,
                extension_data: Vec::from("0123"),
            }]))
            .build()
            .unwrap(),
            concat!(
                concat!(
                    // task_info
                    "01", // length
                    "66"  // opaque data
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
                "00000000000003E8", // time_precision
                "00000000000003E8", // min_batch_size (u64)
                "02",               // batch_mode
                concat!(
                    // batch_config
                    "0000", // length
                ),
                "00000002", // vdaf_type
                concat!(
                    // vdaf_config
                    "0008",             // vdaf_config length
                    "00000000000000FF", // max_measurement (u64)
                ),
                concat!(
                    // extensions
                    "0008", // length
                    concat!(
                        "0000",     // extension_type
                        "0004",     // extension_data length
                        "30313233", // extension_data
                    ),
                ),
            ),
        ),
    ]);

    // Empty task_info is allowed (DAP-19, draft-ietf-ppm-dap#787).
    let config = TaskConfiguration::get_decoded(
        &hex::decode(concat!(
            concat!(
                // task_info
                "00", // length
                ""    // opaque data
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
            "0000000000002710", // min_batch_size (u64)
            "01",               // batch_mode
            concat!(
                // batch_config
                "0000", // length
            ),
            "00000001", // vdaf_type
            concat!(
                // vdaf_config
                "0000", // length
            ),
            concat!(
                // extensions
                "0000", // length
            ),
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(config.task_info().is_empty());
}

#[test]
fn roundtrip_batch_config() {
    roundtrip_encoding(&[
        (
            BatchConfig::Reserved,
            concat!(
                "00",   // batch_mode
                "0000", // batch_config length
            ),
        ),
        (
            BatchConfig::TimeInterval,
            concat!(
                "01",   // batch_mode
                "0000", // batch_config length
            ),
        ),
        (
            BatchConfig::LeaderSelected,
            concat!(
                "02",   // batch_mode
                "0000", // batch_config length
            ),
        ),
        (
            BatchConfig::Unknown {
                batch_mode: 0xFF,
                batch_config: Vec::from([1, 2, 3]),
            },
            concat!(
                "FF",     // batch_mode
                "0003",   // batch_config length
                "010203", // batch_config
            ),
        ),
    ]);

    // A known batch mode with a non-empty batch_config is malformed.
    assert_matches!(
        BatchConfig::get_decoded(
            &hex::decode(concat!(
                "01",     // batch_mode (TimeInterval)
                "0003",   // batch_config length
                "010203", // batch_config (must be empty)
            ))
            .unwrap(),
        ),
        Err(CodecError::Other(_))
    );
}

#[test]
fn roundtrip_vdaf_config() {
    roundtrip_encoding(&[
        (
            VdafConfig::Reserved,
            concat!(
                "00000000", // vdaf_type
                "0000",     // vdaf_config length
                "",         // vdaf_config
            ),
        ),
        (
            VdafConfig::Prio3Count,
            concat!(
                "00000001", // vdaf_type
                "0000",     // vdaf_config length
                "",         // vdaf_config
            ),
        ),
        (
            VdafConfig::Prio3Sum {
                max_measurement: u64::MIN,
            },
            concat!(
                "00000002", // vdaf_type
                "0008",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "0000000000000000", // max_measurement (u64)
                ),
            ),
        ),
        (
            VdafConfig::Prio3Sum {
                max_measurement: 0xFF,
            },
            concat!(
                "00000002", // vdaf_type
                "0008",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "00000000000000FF", // max_measurement (u64)
                ),
            ),
        ),
        (
            VdafConfig::Prio3Sum {
                max_measurement: u64::MAX,
            },
            concat!(
                "00000002", // vdaf_type
                "0008",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "FFFFFFFFFFFFFFFF", // max_measurement (u64)
                ),
            ),
        ),
        (
            VdafConfig::Prio3SumVec {
                length: 12,
                max_measurement: 8,
                chunk_length: 14,
            },
            concat!(
                "00000003", // vdaf_type
                "0010",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "0000000C",         // length
                    "0000000000000008", // max_measurement (u64)
                    "0000000E"          // chunk_length
                ),
            ),
        ),
        (
            VdafConfig::Prio3Histogram {
                length: 256,
                chunk_length: 18,
            },
            concat!(
                "00000004", // vdaf_type
                "0008",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "00000100", // length
                    "00000012", // chunk_length
                ),
            ),
        ),
        (
            VdafConfig::Prio3MultihotCountVec {
                length: 256,
                chunk_length: 18,
                max_weight: 14,
            },
            concat!(
                "00000005", // vdaf_type
                "0010",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "00000100",         // length
                    "00000012",         // chunk_length
                    "000000000000000E", // max_weight (u64)
                ),
            ),
        ),
        (
            VdafConfig::Fake { rounds: 15 },
            concat!(
                "FFFF0000", // vdaf_type
                "0004",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "0000000F", // rounds
                ),
            ),
        ),
        (
            VdafConfig::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                length: 12,
                max_measurement: 8,
                chunk_length: 14,
                proofs: 2,
            },
            concat!(
                "FFFF1003", // vdaf_type
                "0011",     // vdaf_config length
                concat!(
                    // vdaf_config
                    "0000000C",         // length
                    "0000000000000008", // max_measurement (u64)
                    "0000000E",         // chunk_length
                    "02"                // proofs
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_task_extension() {
    roundtrip_encoding(&[
        (
            TaskExtension::Unknown {
                extension_type: TaskExtensionType::Reserved,
                extension_data: Vec::new(),
            },
            concat!(
                "0000", // extension_type
                "0000", // extension_data length
                "",     // extension_data
            ),
        ),
        (
            TaskExtension::Unknown {
                extension_type: TaskExtensionType::Reserved,
                extension_data: Vec::from("0123"),
            },
            concat!(
                "0000",     // extension_type
                "0004",     // extension_data length
                "30313233", // extension_data
            ),
        ),
        (
            TaskExtension::TaskInterval(
                Interval::new(
                    Time::from_time_precision_units(100),
                    Duration::from_time_precision_units(50),
                )
                .unwrap(),
            ),
            concat!(
                "0001",             // extension_type (TaskInterval)
                "0010",             // extension_data length (16 bytes)
                "0000000000000064", // start (100)
                "0000000000000032", // duration (50)
            ),
        ),
    ]);
}

#[test]
fn vdaf_config_wrong_length_prefix() {
    // Prio3Count with a length prefix of 4 instead of 0, followed by 4 trailing bytes.
    assert_matches!(
        VdafConfig::get_decoded(
            &hex::decode(concat!(
                "00000001", // vdaf_type (Prio3Count)
                "0004",     // vdaf_config length (wrong: should be 0)
                "DEADBEEF", // trailing bytes
            ))
            .unwrap(),
        ),
        Err(CodecError::BytesLeftOver(4))
    );

    // Prio3Sum with a length prefix of 12 instead of 8, followed by extra bytes.
    assert_matches!(
        VdafConfig::get_decoded(
            &hex::decode(concat!(
                "00000002",         // vdaf_type (Prio3Sum)
                "000C",             // vdaf_config length (wrong: should be 8)
                "00000000000000FF", // max_measurement (u64)
                "DEADBEEF",         // trailing bytes
            ))
            .unwrap(),
        ),
        Err(CodecError::BytesLeftOver(4))
    );

    // Length prefix too short — sub-buffer won't have enough bytes for the variant.
    assert_matches!(
        VdafConfig::get_decoded(
            &hex::decode(concat!(
                "00000002", // vdaf_type (Prio3Sum)
                "0004",     // vdaf_config length (wrong: should be 8)
                "000000FF", // not enough data
            ))
            .unwrap(),
        ),
        Err(CodecError::Io(_))
    );
}

#[test]
fn roundtrip_task_extension_type() {
    roundtrip_encoding(&[
        (TaskExtensionType::Reserved, "0000"),
        (TaskExtensionType::TaskInterval, "0001"),
    ]);
}

#[test]
fn decode_task_interval_extension_malformed_data() {
    // A TaskInterval extension whose payload isn't a valid Interval fails to decode.
    for bad_data in ["0003010203", "0000"] {
        let bytes = hex::decode(format!("0001{bad_data}")).unwrap();
        assert!(TaskExtension::get_decoded(&bytes).is_err());
    }
}

#[test]
fn task_interval_round_trip() {
    let time_precision = TimePrecision::from_seconds(60);
    let start = Time::from_seconds_since_epoch(3600, &time_precision);
    let duration = Duration::from_time_precision_units(10);

    let ext = TaskExtension::TaskInterval(Interval::new(start, duration).unwrap());
    assert_eq!(ext.extension_type(), TaskExtensionType::TaskInterval);

    let decoded = TaskExtension::get_decoded(&ext.get_encoded().unwrap()).unwrap();
    assert_eq!(ext, decoded);
    assert_matches!(decoded, TaskExtension::TaskInterval(interval) => {
        assert_eq!(interval.start(), start);
        assert_eq!(interval.duration(), duration);
    });
}

#[test]
fn task_configuration_task_interval() {
    let time_precision = TimePrecision::from_seconds(60);
    let task_start = Time::from_seconds_since_epoch(3600, &time_precision);
    let task_duration = Duration::from_time_precision_units(100);

    let config = TaskConfigurationBuilder::new(
        "test".as_bytes().to_vec(),
        Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
        Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
        time_precision,
        10,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
    )
    .with_task_interval(task_start, task_duration)
    .unwrap()
    .build()
    .unwrap();

    let interval = config.task_interval().unwrap();
    assert_eq!(interval.start(), task_start);
    assert_eq!(interval.duration(), task_duration);

    // TaskConfiguration without task_interval extension.
    let config_no_interval = TaskConfigurationBuilder::new(
        "test".as_bytes().to_vec(),
        Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
        Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
        time_precision,
        10,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
    )
    .build()
    .unwrap();

    assert!(config_no_interval.task_interval().is_none());
}

#[test]
fn task_configuration_rejects_duplicate_extensions() {
    let time_precision = TimePrecision::from_seconds(60);
    let task_start = Time::from_seconds_since_epoch(3600, &time_precision);
    let task_duration = Duration::from_time_precision_units(100);
    let interval = Interval::new(task_start, task_duration).unwrap();

    // Construction rejects duplicate extension types.
    assert!(
        TaskConfiguration::new(
            "test".as_bytes().to_vec(),
            Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
            Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
            time_precision,
            10,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            vec![
                TaskExtension::TaskInterval(interval),
                TaskExtension::TaskInterval(interval),
            ],
        )
        .is_err()
    );

    // The builder rejects at build() if both with_extensions and with_task_interval supply a
    // TaskInterval, regardless of call order.
    assert!(
        TaskConfigurationBuilder::new(
            "test".as_bytes().to_vec(),
            Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
            Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
            time_precision,
            10,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
        )
        .with_extensions(vec![TaskExtension::TaskInterval(interval)])
        .with_task_interval(task_start, task_duration)
        .unwrap()
        .build()
        .is_err()
    );
}

#[test]
fn task_configuration_rejects_out_of_order_extensions() {
    let interval = Interval::new(
        Time::from_time_precision_units(0),
        Duration::from_time_precision_units(0),
    )
    .unwrap();

    // Extensions not in strictly increasing order of extension_type (TaskInterval before
    // Reserved).
    assert!(
        TaskConfiguration::new(
            "test".as_bytes().to_vec(),
            Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
            Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
            TimePrecision::from_seconds(60),
            10,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
            vec![
                TaskExtension::TaskInterval(interval),
                TaskExtension::Unknown {
                    extension_type: TaskExtensionType::Reserved,
                    extension_data: Vec::new(),
                },
            ],
        )
        .is_err()
    );
}

#[test]
fn with_task_interval_inserts_in_sorted_order() {
    let time_precision = TimePrecision::from_seconds(60);
    let task_start = Time::from_seconds_since_epoch(3600, &time_precision);
    let task_duration = Duration::from_time_precision_units(10);

    // Caller passes an extension with type > TaskInterval. with_task_interval should insert the
    // TaskInterval extension before it, maintaining strictly increasing order.
    let config = TaskConfigurationBuilder::new(
        "test".as_bytes().to_vec(),
        Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
        Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
        time_precision,
        10,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
    )
    .with_extensions(vec![TaskExtension::Unknown {
        extension_type: TaskExtensionType::Unknown(0xFFFF),
        extension_data: Vec::new(),
    }])
    .with_task_interval(task_start, task_duration)
    .unwrap()
    .build()
    .unwrap();

    let extensions = config.extensions();
    assert_eq!(extensions.len(), 2);
    assert_eq!(
        extensions[0].extension_type(),
        TaskExtensionType::TaskInterval
    );
    assert_eq!(
        extensions[1].extension_type(),
        TaskExtensionType::Unknown(0xFFFF)
    );

    // Also verify the interval data round-trips correctly.
    let interval = config.task_interval().unwrap();
    assert_eq!(interval.start(), task_start);
    assert_eq!(interval.duration(), task_duration);
}

#[test]
fn with_task_interval_rejects_unsorted_caller_extensions() {
    let time_precision = TimePrecision::from_seconds(60);

    // build() validates the final extension order; an unsorted caller list fails.
    assert!(
        TaskConfigurationBuilder::new(
            "test".as_bytes().to_vec(),
            Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
            Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
            time_precision,
            10,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
        )
        .with_extensions(vec![
            TaskExtension::Unknown {
                extension_type: TaskExtensionType::Unknown(0xFFFF),
                extension_data: Vec::new(),
            },
            TaskExtension::Unknown {
                extension_type: TaskExtensionType::Reserved,
                extension_data: Vec::new(),
            },
        ])
        .build()
        .is_err()
    );
}

#[test]
fn task_configuration_rejects_oversized_task_info() {
    let builder = |task_info: Vec<u8>| {
        TaskConfigurationBuilder::new(
            task_info,
            Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
            Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
            TimePrecision::from_seconds(60),
            10,
            BatchConfig::TimeInterval,
            VdafConfig::Prio3Count,
        )
        .build()
    };

    assert!(builder(vec![0u8; 256]).is_err());
    // 255 bytes is the maximum and should succeed.
    assert!(builder(vec![0u8; 255]).is_ok());
}

#[test]
fn unknown_task_extension_type_roundtrips() {
    roundtrip_encoding(&[(TaskExtensionType::Unknown(0x1234), "1234")]);
}

#[test]
fn unknown_task_extension_roundtrips() {
    roundtrip_encoding(&[(
        TaskExtension::Unknown {
            extension_type: TaskExtensionType::Unknown(0x1234),
            extension_data: Vec::from("hello"),
        },
        concat!(
            "1234",       // extension_type
            "0005",       // extension_data length
            "68656C6C6F", // extension_data ("hello")
        ),
    )]);
}

#[test]
fn unknown_vdaf_config_roundtrips() {
    roundtrip_encoding(&[(
        VdafConfig::Unknown {
            vdaf_type: 0xDEADBEEF,
            vdaf_configuration: vec![1, 2, 3, 4],
        },
        concat!(
            "DEADBEEF", // vdaf_type
            "0004",     // vdaf_config length
            "01020304", // vdaf_configuration
        ),
    )]);
}

#[test]
fn unknown_vdaf_config_decodes_from_wire() {
    let vdaf_config = VdafConfig::get_decoded(
        &hex::decode(concat!(
            "99999999", // unknown vdaf_type
            "0003",     // vdaf_config length
            "AABBCC",   // opaque payload
        ))
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        vdaf_config,
        VdafConfig::Unknown {
            vdaf_type: 0x99999999,
            vdaf_configuration: vec![0xAA, 0xBB, 0xCC],
        }
    );
}

#[test]
fn unknown_task_extension_type_in_task_configuration_roundtrips() {
    let config = TaskConfiguration::new(
        "test".as_bytes().to_vec(),
        Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
        Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
        TimePrecision::from_seconds(60),
        10,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
        vec![TaskExtension::Unknown {
            extension_type: TaskExtensionType::Unknown(0x1234),
            extension_data: Vec::from("data"),
        }],
    )
    .unwrap();

    let encoded = config.get_encoded().unwrap();
    let decoded = TaskConfiguration::get_decoded(&encoded).unwrap();
    assert_eq!(config, decoded);
}

#[test]
fn with_task_interval_inserts_after_lower_extensions() {
    let time_precision = TimePrecision::from_seconds(60);
    let task_start = Time::from_seconds_since_epoch(3600, &time_precision);
    let task_duration = Duration::from_time_precision_units(10);

    // Caller passes [Reserved] (< TaskInterval). Result should be [Reserved, TaskInterval].
    let config = TaskConfigurationBuilder::new(
        "test".as_bytes().to_vec(),
        Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
        Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
        time_precision,
        10,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
    )
    .with_extensions(vec![TaskExtension::Unknown {
        extension_type: TaskExtensionType::Reserved,
        extension_data: Vec::new(),
    }])
    .with_task_interval(task_start, task_duration)
    .unwrap()
    .build()
    .unwrap();

    let extensions = config.extensions();
    assert_eq!(extensions.len(), 2);
    assert_eq!(extensions[0].extension_type(), TaskExtensionType::Reserved);
    assert_eq!(
        extensions[1].extension_type(),
        TaskExtensionType::TaskInterval
    );
}

#[test]
fn builder_task_interval_survives_later_with_extensions() {
    let time_precision = TimePrecision::from_seconds(60);
    let task_start = Time::from_seconds_since_epoch(3600, &time_precision);
    let task_duration = Duration::from_time_precision_units(10);

    // Calling with_extensions after with_task_interval must NOT drop the interval; the interval
    // is tracked separately and inserted at build time regardless of call order.
    let config = TaskConfigurationBuilder::new(
        "test".as_bytes().to_vec(),
        Url::try_from("https://leader.example.com/".as_ref()).unwrap(),
        Url::try_from("https://helper.example.com/".as_ref()).unwrap(),
        time_precision,
        10,
        BatchConfig::TimeInterval,
        VdafConfig::Prio3Count,
    )
    .with_task_interval(task_start, task_duration)
    .unwrap()
    .with_extensions(vec![TaskExtension::Unknown {
        extension_type: TaskExtensionType::Reserved,
        extension_data: Vec::new(),
    }])
    .build()
    .unwrap();

    assert_eq!(config.extensions().len(), 2);
    let interval = config.task_interval().unwrap();
    assert_eq!(interval.start(), task_start);
    assert_eq!(interval.duration(), task_duration);
}

#[test]
fn decode_task_configuration_rejects_out_of_order_extensions_on_wire() {
    // Wire-level test: TaskConfiguration with extensions in wrong order should fail to decode.
    assert_matches!(
        TaskConfiguration::get_decoded(
            &hex::decode(concat!(
                concat!(
                    // task_info
                    "01", // length
                    "66"  // opaque data ("f")
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
                "0000000000002710", // min_batch_size (u64)
                "01",               // batch_mode
                concat!(
                    // batch_config
                    "0000", // length
                ),
                "00000001", // vdaf_type (Prio3Count)
                concat!(
                    // vdaf_config
                    "0000", // length
                ),
                concat!(
                    // extensions: TaskInterval (0x0001) then Reserved (0x0000) — wrong order
                    "0018", // length (24 bytes total)
                    concat!(
                        "0001",             // extension_type (TaskInterval)
                        "0010",             // extension_data length (16 bytes)
                        "0000000000000000", // start
                        "0000000000000000", // duration
                    ),
                    concat!(
                        "0000", // extension_type (Reserved)
                        "0000", // extension_data length
                    ),
                ),
            ))
            .unwrap(),
        ),
        Err(CodecError::Other(_))
    );
}

#[test]
fn decode_unknown_task_extension_type_from_wire() {
    // A TaskConfiguration with an unknown extension type should decode successfully.
    let config = TaskConfiguration::get_decoded(
        &hex::decode(concat!(
            concat!(
                // task_info
                "01", // length
                "66"  // opaque data ("f")
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
            "0000000000002710", // min_batch_size (u64)
            "01",               // batch_mode
            concat!(
                // batch_config
                "0000", // length
            ),
            "00000001", // vdaf_type (Prio3Count)
            concat!(
                // vdaf_config
                "0000", // length
            ),
            concat!(
                // extensions: single unknown extension type 0xBEEF
                "0008", // length
                concat!(
                    "BEEF",     // extension_type (unknown)
                    "0004",     // extension_data length
                    "DEADBEEF", // extension_data
                ),
            ),
        ))
        .unwrap(),
    )
    .unwrap();

    let extensions = config.extensions();
    assert_eq!(extensions.len(), 1);
    assert_matches!(
        &extensions[0],
        TaskExtension::Unknown { extension_type, extension_data } => {
            assert_eq!(*extension_type, TaskExtensionType::Unknown(0xBEEF));
            assert_eq!(extension_data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        }
    );
}

#[test]
fn task_extension_type_equality_by_codepoint() {
    // Equality, ordering, and hashing are all defined by the underlying codepoint, so an
    // Unknown that aliases a named codepoint compares and hashes equal to the named variant.
    assert_eq!(
        TaskExtensionType::Unknown(0x0001),
        TaskExtensionType::TaskInterval
    );
    assert_eq!(
        TaskExtensionType::Unknown(0x0000),
        TaskExtensionType::Reserved
    );
    assert_eq!(
        TaskExtensionType::TaskInterval.cmp(&TaskExtensionType::Unknown(0x0001)),
        std::cmp::Ordering::Equal
    );

    let mut set = HashSet::new();
    set.insert(TaskExtensionType::TaskInterval);
    assert!(set.contains(&TaskExtensionType::Unknown(0x0001)));
}

#[test]
fn oversized_unknown_vdaf_config_fails_to_encode() {
    // VdafConfig::Unknown with a payload longer than u16::MAX must return an encode error
    // rather than panicking.
    let config = VdafConfig::Unknown {
        vdaf_type: 0xDEADBEEF,
        vdaf_configuration: vec![0u8; usize::from(u16::MAX) + 1],
    };
    assert_matches!(config.get_encoded(), Err(CodecError::Other(_)));
    assert!(config.encoded_len().is_none());
}

#[test]
fn unknown_variants_with_known_codepoint_normalize_on_decode() {
    // A hand-constructed `Unknown` with an in-range codepoint normalizes to the canonical typed
    // variant on decode, so it does not survive a round-trip.

    // BatchConfig::Unknown { batch_mode: 1 } encodes identically to TimeInterval.
    let batch = BatchConfig::Unknown {
        batch_mode: 1,
        batch_config: Vec::new(),
    };
    let decoded = BatchConfig::get_decoded(&batch.get_encoded().unwrap()).unwrap();
    assert_eq!(decoded, BatchConfig::TimeInterval);
    assert_ne!(decoded, batch);

    // TaskExtension::Unknown carrying the TaskInterval codepoint (and a valid interval payload)
    // decodes back as the typed TaskInterval variant.
    let interval = Interval::new(
        Time::from_time_precision_units(100),
        Duration::from_time_precision_units(50),
    )
    .unwrap();
    let extension = TaskExtension::Unknown {
        extension_type: TaskExtensionType::Unknown(0x0001),
        extension_data: interval.get_encoded().unwrap(),
    };
    let decoded = TaskExtension::get_decoded(&extension.get_encoded().unwrap()).unwrap();
    assert_eq!(decoded, TaskExtension::TaskInterval(interval));
    assert_ne!(decoded, extension);

    // VdafConfig::Unknown carrying a known type code (and matching payload) decodes as the typed
    // variant.
    let vdaf = VdafConfig::Unknown {
        vdaf_type: 0x00000001, // Prio3Count
        vdaf_configuration: Vec::new(),
    };
    let decoded = VdafConfig::get_decoded(&vdaf.get_encoded().unwrap()).unwrap();
    assert_eq!(decoded, VdafConfig::Prio3Count);
    assert_ne!(decoded, vdaf);
}
