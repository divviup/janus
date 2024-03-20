use crate::{
    query_type, roundtrip_encoding, AggregateShare, AggregateShareAad, AggregateShareReq,
    AggregationJobContinueReq, AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep,
    BatchId, BatchSelector, Collection, CollectionReq, Duration, Extension, ExtensionType,
    FixedSize, FixedSizeQuery, HpkeAeadId, HpkeCiphertext, HpkeConfig, HpkeConfigId,
    HpkeConfigList, HpkeKdfId, HpkeKemId, HpkePublicKey, InputShareAad, Interval,
    PartialBatchSelector, PlaintextInputShare, PrepareContinue, PrepareError, PrepareInit,
    PrepareResp, PrepareStepResult, Query, Report, ReportId, ReportIdChecksum, ReportMetadata,
    ReportShare, Role, TaskId, Time, TimeInterval, Url,
};
use assert_matches::assert_matches;
use prio::{
    codec::{CodecError, Decode, Encode},
    topology::ping_pong::PingPongMessage,
};
use serde_test::{assert_de_tokens_error, assert_tokens, Token};

#[test]
fn roundtrip_url() {
    for (test, len) in [
        ("https://example.com/", [0u8, 20]),
        ("https://example.com", [0u8, 19]),
        (
            &("http://".to_string()
                + &"h".repeat(Into::<usize>::into(u16::MAX) - "http://".len() - 1)
                + "/"),
            [u8::MAX, u8::MAX],
        ),
    ] {
        roundtrip_encoding(&[(
            Url::try_from(test.as_ref()).unwrap(),
            &(hex::encode(len) + &hex::encode(test)),
        )])
    }

    // Zero length string
    assert_matches!(
        Url::get_decoded(&hex::decode(concat!("0000")).unwrap()),
        Err(CodecError::Other(_))
    );

    // Non-ascii string
    assert_matches!(
        Url::get_decoded(&hex::decode(concat!("0001FF")).unwrap()),
        Err(CodecError::Other(_))
    );
}

#[test]
fn roundtrip_duration() {
    roundtrip_encoding(&[
        (Duration::from_seconds(u64::MIN), "0000000000000000"),
        (Duration::from_seconds(12345), "0000000000003039"),
        (Duration::from_seconds(u64::MAX), "FFFFFFFFFFFFFFFF"),
    ])
}

#[test]
fn roundtrip_time() {
    roundtrip_encoding(&[
        (Time::from_seconds_since_epoch(u64::MIN), "0000000000000000"),
        (Time::from_seconds_since_epoch(12345), "0000000000003039"),
        (Time::from_seconds_since_epoch(u64::MAX), "FFFFFFFFFFFFFFFF"),
    ])
}

#[test]
fn roundtrip_interval() {
    Interval::new(
        Time::from_seconds_since_epoch(1),
        Duration::from_seconds(u64::MAX),
    )
    .unwrap_err();

    let encoded = Interval {
        start: Time::from_seconds_since_epoch(1),
        duration: Duration::from_seconds(u64::MAX),
    }
    .get_encoded()
    .unwrap();
    assert_eq!(
        encoded,
        hex::decode(concat!(
            "0000000000000001", // start
            "FFFFFFFFFFFFFFFF", // duration))
        ))
        .unwrap()
    );

    assert_matches!(Interval::get_decoded(&encoded), Err(CodecError::Other(_)));

    roundtrip_encoding(&[
        (
            Interval {
                start: Time::from_seconds_since_epoch(u64::MIN),
                duration: Duration::from_seconds(u64::MAX),
            },
            concat!(
                "0000000000000000", // start
                "FFFFFFFFFFFFFFFF", // duration
            ),
        ),
        (
            Interval {
                start: Time::from_seconds_since_epoch(54321),
                duration: Duration::from_seconds(12345),
            },
            concat!(
                "000000000000D431", // start
                "0000000000003039", // duration
            ),
        ),
        (
            Interval {
                start: Time::from_seconds_since_epoch(u64::MAX),
                duration: Duration::from_seconds(u64::MIN),
            },
            concat!(
                "FFFFFFFFFFFFFFFF", // start
                "0000000000000000", // duration
            ),
        ),
    ])
}

#[test]
fn roundtrip_batch_id() {
    roundtrip_encoding(&[
        (
            BatchId::from([u8::MIN; BatchId::LEN]),
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            BatchId::from([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ),
        (
            BatchId::from([u8::MAX; TaskId::LEN]),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ),
    ])
}

#[test]
fn roundtrip_report_id() {
    roundtrip_encoding(&[
        (
            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            "0102030405060708090a0b0c0d0e0f10",
        ),
        (
            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
            "100f0e0d0c0b0a090807060504030201",
        ),
    ])
}

#[test]
fn roundtrip_role() {
    roundtrip_encoding(&[
        (Role::Collector, "00"),
        (Role::Client, "01"),
        (Role::Leader, "02"),
        (Role::Helper, "03"),
    ]);
}

#[test]
fn roundtrip_hpke_config_id() {
    roundtrip_encoding(&[
        (HpkeConfigId(u8::MIN), "00"),
        (HpkeConfigId(10), "0A"),
        (HpkeConfigId(u8::MAX), "FF"),
    ])
}

#[test]
fn roundtrip_task_id() {
    roundtrip_encoding(&[
        (
            TaskId::from([u8::MIN; TaskId::LEN]),
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            TaskId::from([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        ),
        (
            TaskId::from([u8::MAX; TaskId::LEN]),
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ),
    ])
}

#[test]
fn roundtrip_hpke_kem_id() {
    roundtrip_encoding(&[
        (HpkeKemId::P256HkdfSha256, "0010"),
        (HpkeKemId::X25519HkdfSha256, "0020"),
    ])
}

#[test]
fn roundtrip_hpke_kdf_id() {
    roundtrip_encoding(&[
        (HpkeKdfId::HkdfSha256, "0001"),
        (HpkeKdfId::HkdfSha384, "0002"),
        (HpkeKdfId::HkdfSha512, "0003"),
    ])
}

#[test]
fn roundtrip_hpke_aead_id() {
    roundtrip_encoding(&[
        (HpkeAeadId::Aes128Gcm, "0001"),
        (HpkeAeadId::Aes256Gcm, "0002"),
        (HpkeAeadId::ChaCha20Poly1305, "0003"),
    ])
}

#[test]
fn roundtrip_extension() {
    roundtrip_encoding(&[
        (
            Extension::new(ExtensionType::Tbd, Vec::new()),
            concat!(
                "0000", // extension_type
                concat!(
                    // extension_data
                    "0000", // length
                    "",     // opaque data
                ),
            ),
        ),
        (
            Extension::new(ExtensionType::Taskprov, Vec::from("0123")),
            concat!(
                "FF00", // extension_type
                concat!(
                    // extension_data
                    "0004",     // length
                    "30313233", // opaque data
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_extension_type() {
    roundtrip_encoding(&[(ExtensionType::Tbd, "0000")])
}

#[test]
fn roundtrip_hpke_ciphertext() {
    roundtrip_encoding(&[
        (
            HpkeCiphertext::new(HpkeConfigId::from(10), Vec::from("0123"), Vec::from("4567")),
            concat!(
                "0A", // config_id
                concat!(
                    // encapsulated_key
                    "0004",     // length
                    "30313233", // opaque data
                ),
                concat!(
                    // payload
                    "00000004", // length
                    "34353637", // opaque data
                ),
            ),
        ),
        (
            HpkeCiphertext::new(HpkeConfigId::from(12), Vec::from("01234"), Vec::from("567")),
            concat!(
                "0C", // config_id
                concat!(
                    // encapsulated_key
                    "0005",       // length
                    "3031323334", // opaque data
                ),
                concat!(
                    // payload
                    "00000003", // length
                    "353637",   // opaque data
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_hpke_public_key() {
    roundtrip_encoding(&[
        (
            HpkePublicKey::from(Vec::new()),
            concat!(
                "0000", // length
                "",     // opaque data
            ),
        ),
        (
            HpkePublicKey::from(Vec::from("0123456789abcdef")),
            concat!(
                "0010",                             // length
                "30313233343536373839616263646566"  // opaque data
            ),
        ),
    ])
}

#[test]
fn roundtrip_hpke_config() {
    roundtrip_encoding(&[
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(23),
                HpkeKemId::X25519HkdfSha256,
                HpkeKdfId::HkdfSha256,
                HpkeAeadId::ChaCha20Poly1305,
                HpkePublicKey::from(Vec::from("0123456789abcdef")),
            ),
            concat!(
                "17",   // id
                "0020", // kem_id
                "0001", // kdf_id
                "0003", // aead_id
                concat!(
                    // public_key
                    "0010",                             // length
                    "30313233343536373839616263646566", // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::Other(0x9999),
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "9999", // kem_id
                "0003", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::Other(0x9999),
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "9999", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
        (
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Other(0x9999),
                HpkePublicKey::from(Vec::new()),
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "9999", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
    ])
}

#[test]
fn roundtrip_hpke_config_list() {
    roundtrip_encoding(&[(
        HpkeConfigList::new(Vec::from([
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Aes256Gcm,
                HpkePublicKey::from(Vec::new()),
            ),
            HpkeConfig::new(
                HpkeConfigId::from(12),
                HpkeKemId::P256HkdfSha256,
                HpkeKdfId::HkdfSha512,
                HpkeAeadId::Other(0x9999),
                HpkePublicKey::from(Vec::new()),
            ),
        ])),
        concat!(
            "0012",
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "0002", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
            concat!(
                "0C",   // id
                "0010", // kem_id
                "0003", // kdf_id
                "9999", // aead_id
                concat!(
                    // public_key
                    "0000", // length
                    "",     // opaque data
                )
            ),
        ),
    )]);
}

#[test]
fn roundtrip_report_metadata() {
    roundtrip_encoding(&[
        (
            ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(12345),
            ),
            concat!(
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "0000000000003039",                 // time
            ),
        ),
        (
            ReportMetadata::new(
                ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                Time::from_seconds_since_epoch(54321),
            ),
            concat!(
                "100F0E0D0C0B0A090807060504030201", // report_id
                "000000000000D431",                 // time
            ),
        ),
    ])
}

#[test]
fn roundtrip_plaintext_input_share() {
    roundtrip_encoding(&[
        (
            PlaintextInputShare::new(Vec::new(), Vec::from("0123")),
            concat!(
                concat!(
                    // extensions
                    "0000", // length
                ),
                concat!(
                    // payload
                    "00000004", // length
                    "30313233", // opaque data
                )
            ),
        ),
        (
            PlaintextInputShare::new(
                Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                Vec::from("4567"),
            ),
            concat!(
                concat!(
                    // extensions
                    "0008", // length
                    concat!(
                        "0000", // extension_type
                        concat!(
                            // extension_data
                            "0004",     // length
                            "30313233", // opaque data
                        ),
                    ),
                ),
                concat!(
                    // payload
                    "00000004", // length
                    "34353637", // opaque data
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_report() {
    roundtrip_encoding(&[
        (
            Report::new(
                ReportMetadata::new(
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Time::from_seconds_since_epoch(12345),
                ),
                Vec::new(),
                HpkeCiphertext::new(
                    HpkeConfigId::from(42),
                    Vec::from("012345"),
                    Vec::from("543210"),
                ),
                HpkeCiphertext::new(HpkeConfigId::from(13), Vec::from("abce"), Vec::from("abfd")),
            ),
            concat!(
                concat!(
                    // metadata
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "0000000000003039",                 // time
                ),
                concat!(
                    // public_share
                    "00000000", // length
                ),
                concat!(
                    // leader_encrypted_input_share
                    "2A", // config_id
                    concat!(
                        // encapsulated_context
                        "0006",         // length
                        "303132333435"  // opaque data
                    ),
                    concat!(
                        // payload
                        "00000006",     // length
                        "353433323130", // opaque data
                    ),
                ),
                concat!(
                    // helper_encrypted_input_share
                    "0D", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "61626365", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "61626664", // opaque data
                    ),
                ),
            ),
        ),
        (
            Report::new(
                ReportMetadata::new(
                    ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    Time::from_seconds_since_epoch(54321),
                ),
                Vec::from("3210"),
                HpkeCiphertext::new(
                    HpkeConfigId::from(42),
                    Vec::from("012345"),
                    Vec::from("543210"),
                ),
                HpkeCiphertext::new(HpkeConfigId::from(13), Vec::from("abce"), Vec::from("abfd")),
            ),
            concat!(
                concat!(
                    // metadata
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "000000000000D431",                 // time
                ),
                concat!(
                    // public_share
                    "00000004", // length
                    "33323130", // opaque data
                ),
                concat!(
                    // leader_encrypted_input_share
                    "2A", // config_id
                    concat!(
                        // encapsulated_context
                        "0006",         // length
                        "303132333435"  // opaque data
                    ),
                    concat!(
                        // payload
                        "00000006",     // length
                        "353433323130", // opaque data
                    ),
                ),
                concat!(
                    // helper_encrypted_input_share
                    "0D", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "61626365", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "61626664", // opaque data
                    ),
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_fixed_size_query() {
    roundtrip_encoding(&[
        (
            FixedSizeQuery::ByBatchId {
                batch_id: BatchId::from([10u8; 32]),
            },
            concat!(
                "00",                                                               // query_type
                "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
            ),
        ),
        (
            FixedSizeQuery::CurrentBatch,
            concat!(
                "01", // query_type
            ),
        ),
    ])
}

#[test]
fn roundtrip_query() {
    // TimeInterval.
    roundtrip_encoding(&[
        (
            Query::<TimeInterval> {
                query_body: Interval::new(
                    Time::from_seconds_since_epoch(54321),
                    Duration::from_seconds(12345),
                )
                .unwrap(),
            },
            concat!(
                "01", // query_type
                concat!(
                    // query_body
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
        ),
        (
            Query::<TimeInterval> {
                query_body: Interval::new(
                    Time::from_seconds_since_epoch(48913),
                    Duration::from_seconds(44721),
                )
                .unwrap(),
            },
            concat!(
                "01", // query_type
                concat!(
                    // query_body
                    "000000000000BF11", // start
                    "000000000000AEB1", // duration
                ),
            ),
        ),
    ]);

    // FixedSize.
    roundtrip_encoding(&[
        (
            Query::<FixedSize> {
                query_body: FixedSizeQuery::ByBatchId {
                    batch_id: BatchId::from([10u8; 32]),
                },
            },
            concat!(
                "02", // query_type
                concat!(
                    // query_body
                    "00", // query_type
                    "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                ),
            ),
        ),
        (
            Query::<FixedSize> {
                query_body: FixedSizeQuery::CurrentBatch,
            },
            concat!(
                "02", // query_type
                concat!(
                    // query_body
                    "01", // query_type
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_collection_req() {
    // TimeInterval.
    roundtrip_encoding(&[
        (
            CollectionReq::<TimeInterval> {
                query: Query {
                    query_body: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                },
                aggregation_parameter: Vec::new(),
            },
            concat!(
                concat!(
                    // query
                    "01", // query_type
                    concat!(
                        // query_body
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                ),
                concat!(
                    // aggregation_parameter
                    "00000000", // length
                    "",         // opaque data
                ),
            ),
        ),
        (
            CollectionReq::<TimeInterval> {
                query: Query {
                    query_body: Interval::new(
                        Time::from_seconds_since_epoch(48913),
                        Duration::from_seconds(44721),
                    )
                    .unwrap(),
                },
                aggregation_parameter: Vec::from("012345"),
            },
            concat!(
                concat!(
                    // query
                    "01", // query_type
                    concat!(
                        // batch_interval
                        "000000000000BF11", // start
                        "000000000000AEB1", // duration
                    ),
                ),
                concat!(
                    // aggregation_parameter
                    "00000006",     // length
                    "303132333435", // opaque data
                ),
            ),
        ),
    ]);

    // FixedSize.
    roundtrip_encoding(&[
        (
            CollectionReq::<FixedSize> {
                query: Query {
                    query_body: FixedSizeQuery::ByBatchId {
                        batch_id: BatchId::from([10u8; 32]),
                    },
                },
                aggregation_parameter: Vec::new(),
            },
            concat!(
                concat!(
                    "02", // query_type
                    concat!(
                        // query_body
                        "00", // query_type
                        "0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A", // batch_id
                    ),
                ),
                concat!(
                    // aggregation_parameter
                    "00000000", // length
                    "",         // opaque data
                ),
            ),
        ),
        (
            CollectionReq::<FixedSize> {
                query: Query::<FixedSize> {
                    query_body: FixedSizeQuery::CurrentBatch,
                },
                aggregation_parameter: Vec::from("012345"),
            },
            concat!(
                concat!(
                    "02", // query_type
                    concat!(
                        // query_body
                        "01", // query_type
                    ),
                ),
                concat!(
                    // aggregation_parameter
                    "00000006",     // length
                    "303132333435", // opaque data
                ),
            ),
        ),
    ]);
}

#[test]
fn roundtrip_partial_batch_selector() {
    // TimeInterval.
    roundtrip_encoding(&[(
        PartialBatchSelector::new_time_interval(),
        concat!(
            "01", // query_type
        ),
    )]);

    // FixedSize.
    roundtrip_encoding(&[
        (
            PartialBatchSelector::new_fixed_size(BatchId::from([3u8; 32])),
            concat!(
                "02",                                                               // query_type
                "0303030303030303030303030303030303030303030303030303030303030303", // batch_id
            ),
        ),
        (
            PartialBatchSelector::new_fixed_size(BatchId::from([4u8; 32])),
            concat!(
                "02",                                                               // query_type
                "0404040404040404040404040404040404040404040404040404040404040404", // batch_id
            ),
        ),
    ])
}

#[test]
fn roundtrip_collection() {
    let interval = Interval {
        start: Time::from_seconds_since_epoch(54321),
        duration: Duration::from_seconds(12345),
    };
    // TimeInterval.
    roundtrip_encoding(&[
        (
            Collection {
                partial_batch_selector: PartialBatchSelector::new_time_interval(),
                report_count: 0,
                interval,
                leader_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(10),
                    Vec::from("0123"),
                    Vec::from("4567"),
                ),
                helper_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(12),
                    Vec::from("01234"),
                    Vec::from("567"),
                ),
            },
            concat!(
                concat!(
                    // partial_batch_selector
                    "01", // query_type
                ),
                "0000000000000000", // report_count
                concat!(
                    // interval
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
                concat!(
                    // leader_encrypted_agg_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                ),
                concat!(
                    // helper_encrypted_agg_share
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "353637",   // opaque data
                    ),
                )
            ),
        ),
        (
            Collection {
                partial_batch_selector: PartialBatchSelector::new_time_interval(),
                report_count: 23,
                interval,
                leader_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(10),
                    Vec::from("0123"),
                    Vec::from("4567"),
                ),
                helper_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(12),
                    Vec::from("01234"),
                    Vec::from("567"),
                ),
            },
            concat!(
                concat!(
                    // partial_batch_selector
                    "01", // query_type
                ),
                "0000000000000017", // report_count
                concat!(
                    // interval
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
                concat!(
                    // leader_encrypted_agg_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                ),
                concat!(
                    // helper_encrypted_agg_share
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "353637",   // opaque data
                    ),
                )
            ),
        ),
    ]);

    // FixedSize.
    roundtrip_encoding(&[
        (
            Collection {
                partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                    [3u8; 32],
                )),
                report_count: 0,
                interval,
                leader_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(10),
                    Vec::from("0123"),
                    Vec::from("4567"),
                ),
                helper_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(12),
                    Vec::from("01234"),
                    Vec::from("567"),
                ),
            },
            concat!(
                concat!(
                    // partial_batch_selector
                    "02", // query_type
                    "0303030303030303030303030303030303030303030303030303030303030303", // batch_id
                ),
                "0000000000000000", // report_count
                concat!(
                    // interval
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
                concat!(
                    // leader_encrypted_agg_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                ),
                concat!(
                    // helper_encrypted_agg_share
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "353637",   // opaque data
                    ),
                )
            ),
        ),
        (
            Collection {
                partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from(
                    [4u8; 32],
                )),
                report_count: 23,
                interval,
                leader_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(10),
                    Vec::from("0123"),
                    Vec::from("4567"),
                ),
                helper_encrypted_agg_share: HpkeCiphertext::new(
                    HpkeConfigId::from(12),
                    Vec::from("01234"),
                    Vec::from("567"),
                ),
            },
            concat!(
                concat!(
                    // partial_batch_selector
                    "02", // query_type
                    "0404040404040404040404040404040404040404040404040404040404040404", // batch_id
                ),
                "0000000000000017", // report_count
                concat!(
                    // interval
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
                concat!(
                    // leader_encrypted_agg_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "34353637", // opaque data
                    ),
                ),
                concat!(
                    // helper_encrypted_agg_share
                    "0C", // config_id
                    concat!(
                        // encapsulated_context
                        "0005",       // length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "353637",   // opaque data
                    ),
                )
            ),
        ),
    ]);
}

#[test]
fn roundtrip_code() {
    roundtrip_encoding(&[
        (query_type::Code::Reserved, "00"),
        (query_type::Code::TimeInterval, "01"),
        (query_type::Code::FixedSize, "02"),
    ])
}

#[test]
fn roundtrip_report_share() {
    roundtrip_encoding(&[
        (
            ReportShare {
                metadata: ReportMetadata::new(
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Time::from_seconds_since_epoch(54321),
                ),
                public_share: Vec::new(),
                encrypted_input_share: HpkeCiphertext::new(
                    HpkeConfigId::from(42),
                    Vec::from("012345"),
                    Vec::from("543210"),
                ),
            },
            concat!(
                concat!(
                    // metadata
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "000000000000D431",                 // time
                ),
                concat!(
                    // public_share
                    "00000000", // length
                    "",         // opaque data
                ),
                concat!(
                    // encrypted_input_share
                    "2A", // config_id
                    concat!(
                        // encapsulated_context
                        "0006",         // length
                        "303132333435", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000006",     // length
                        "353433323130", // opaque data
                    ),
                ),
            ),
        ),
        (
            ReportShare {
                metadata: ReportMetadata::new(
                    ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    Time::from_seconds_since_epoch(73542),
                ),
                public_share: Vec::from("0123"),
                encrypted_input_share: HpkeCiphertext::new(
                    HpkeConfigId::from(13),
                    Vec::from("abce"),
                    Vec::from("abfd"),
                ),
            },
            concat!(
                concat!(
                    // metadata
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "0000000000011F46",                 // time
                ),
                concat!(
                    // public_share
                    "00000004", // length
                    "30313233", // opaque data
                ),
                concat!(
                    // encrypted_input_share
                    "0D", // config_id
                    concat!(
                        // encapsulated_context
                        "0004",     // length
                        "61626365", // opaque data
                    ),
                    concat!(
                        // payload
                        "00000004", // length
                        "61626664", // opaque data
                    ),
                ),
            ),
        ),
    ])
}

#[test]
fn roundtrip_prepare_init() {
    roundtrip_encoding(&[
        (
            PrepareInit {
                report_share: ReportShare {
                    metadata: ReportMetadata::new(
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(54321),
                    ),
                    public_share: Vec::new(),
                    encrypted_input_share: HpkeCiphertext::new(
                        HpkeConfigId::from(42),
                        Vec::from("012345"),
                        Vec::from("543210"),
                    ),
                },
                message: PingPongMessage::Initialize {
                    prep_share: Vec::from("012345"),
                },
            },
            concat!(
                concat!(
                    // report_share
                    concat!(
                        // metadata
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "000000000000D431",                 // time
                    ),
                    concat!(
                        // public_share
                        "00000000", // length
                        "",         // opaque data
                    ),
                    concat!(
                        // encrypted_input_share
                        "2A", // config_id
                        concat!(
                            // encapsulated_context
                            "0006",         // length
                            "303132333435", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000006",     // length
                            "353433323130", // opaque data
                        ),
                    ),
                ),
                concat!(
                    // message
                    "0000000b", // ping pong message length
                    "00",       // ping pong message type
                    concat!(
                        "00000006",     // prep_share length
                        "303132333435", // opaque data
                    )
                )
            ),
        ),
        (
            PrepareInit {
                report_share: ReportShare {
                    metadata: ReportMetadata::new(
                        ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        Time::from_seconds_since_epoch(73542),
                    ),
                    public_share: Vec::from("0123"),
                    encrypted_input_share: HpkeCiphertext::new(
                        HpkeConfigId::from(13),
                        Vec::from("abce"),
                        Vec::from("abfd"),
                    ),
                },
                message: PingPongMessage::Finish {
                    prep_msg: Vec::new(),
                },
            },
            concat!(
                concat!(
                    // report_share
                    concat!(
                        // metadata
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "0000000000011F46",                 // time
                    ),
                    concat!(
                        // public_share
                        "00000004", // length
                        "30313233", // opaque data
                    ),
                    concat!(
                        // encrypted_input_share
                        "0D", // config_id
                        concat!(
                            // encapsulated_context
                            "0004",     // length
                            "61626365", // opaque data
                        ),
                        concat!(
                            // payload
                            "00000004", // length
                            "61626664", // opaque data
                        ),
                    ),
                ),
                concat!(
                    // message
                    "00000005", // ping pong message length
                    "02",       // ping pong message type
                    concat!(
                        "00000000", // prep_msg length
                        ""          // opaque data
                    )
                )
            ),
        ),
    ])
}

#[test]
fn roundtrip_prepare_resp() {
    roundtrip_encoding(&[
        (
            PrepareResp {
                report_id: ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                result: PrepareStepResult::Continue {
                    message: PingPongMessage::Continue {
                        prep_msg: Vec::from("012345"),
                        prep_share: Vec::from("6789"),
                    },
                },
            },
            concat!(
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "00",                               // prepare_step_result
                concat!(
                    // message
                    "00000013", // ping pong message length
                    "01",       // ping pong message type
                    concat!(
                        "00000006",     // prep_msg length
                        "303132333435", // opaque data
                    ),
                    concat!(
                        "00000004", // prep_share length
                        "36373839", // opaque data
                    )
                ),
            ),
        ),
        (
            PrepareResp {
                report_id: ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                result: PrepareStepResult::Finished,
            },
            concat!(
                "100F0E0D0C0B0A090807060504030201", // report_id
                "01",                               // prepare_step_result
            ),
        ),
        (
            PrepareResp {
                report_id: ReportId::from([255; 16]),
                result: PrepareStepResult::Reject(PrepareError::VdafPrepError),
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // report_id
                "02",                               // prepare_step_result
                "05",                               // report_share_error
            ),
        ),
    ])
}

#[test]
fn roundtrip_report_share_error() {
    roundtrip_encoding(&[
        (PrepareError::BatchCollected, "00"),
        (PrepareError::ReportReplayed, "01"),
        (PrepareError::ReportDropped, "02"),
        (PrepareError::HpkeUnknownConfigId, "03"),
        (PrepareError::HpkeDecryptError, "04"),
        (PrepareError::VdafPrepError, "05"),
        (PrepareError::BatchSaturated, "06"),
        (PrepareError::TaskExpired, "07"),
        (PrepareError::InvalidMessage, "08"),
        (PrepareError::ReportTooEarly, "09"),
    ])
}

#[test]
fn roundtrip_aggregation_job_initialize_req() {
    // TimeInterval.
    roundtrip_encoding(&[(
        AggregationJobInitializeReq {
            aggregation_parameter: Vec::from("012345"),
            partial_batch_selector: PartialBatchSelector::new_time_interval(),
            prepare_inits: Vec::from([
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                            Time::from_seconds_since_epoch(54321),
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    message: PingPongMessage::Initialize {
                        prep_share: Vec::from("012345"),
                    },
                },
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            Time::from_seconds_since_epoch(73542),
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                    message: PingPongMessage::Finish {
                        prep_msg: Vec::new(),
                    },
                },
            ]),
        },
        concat!(
            concat!(
                // aggregation_parameter
                "00000006",     // length
                "303132333435", // opaque data
            ),
            concat!(
                // partial_batch_selector
                "01", // query_type
            ),
            concat!(
                // prepare_inits
                "00000076", // length
                concat!(
                    concat!(
                        // report_share
                        concat!(
                            // metadata
                            "0102030405060708090A0B0C0D0E0F10", // report_id
                            "000000000000D431",                 // time
                        ),
                        concat!(
                            // public_share
                            "00000000", // length
                            "",         // opaque data
                        ),
                        concat!(
                            // encrypted_input_share
                            "2A", // config_id
                            concat!(
                                // encapsulated_context
                                "0006",         // length
                                "303132333435", // opaque data
                            ),
                            concat!(
                                // payload
                                "00000006",     // length
                                "353433323130", // opaque data
                            ),
                        ),
                    ),
                    concat!(
                        // message
                        "0000000b", // ping pong message length
                        "00",       // ping pong message type
                        concat!(
                            "00000006",     // prep_share length
                            "303132333435", // opaque data
                        ),
                    )
                ),
                concat!(
                    concat!(
                        concat!(
                            // metadata
                            "100F0E0D0C0B0A090807060504030201", // report_id
                            "0000000000011F46",                 // time
                        ),
                        concat!(
                            // public_share
                            "00000004", // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // encrypted_input_share
                            "0D", // config_id
                            concat!(
                                // encapsulated_context
                                "0004",     // length
                                "61626365", // opaque data
                            ),
                            concat!(
                                // payload
                                "00000004", // length
                                "61626664", // opaque data
                            ),
                        ),
                    ),
                    concat!(
                        // message
                        "00000005", // ping pong message length
                        "02",       // ping pong message type
                        concat!(
                            "00000000", // prep_msg length
                            ""          // opaque data
                        )
                    )
                ),
            ),
        ),
    )]);

    // FixedSize.
    roundtrip_encoding(&[(
        AggregationJobInitializeReq::<FixedSize> {
            aggregation_parameter: Vec::from("012345"),
            partial_batch_selector: PartialBatchSelector::new_fixed_size(BatchId::from([2u8; 32])),
            prepare_inits: Vec::from([
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                            Time::from_seconds_since_epoch(54321),
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    message: PingPongMessage::Initialize {
                        prep_share: Vec::from("012345"),
                    },
                },
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            Time::from_seconds_since_epoch(73542),
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                    message: PingPongMessage::Finish {
                        prep_msg: Vec::new(),
                    },
                },
            ]),
        },
        concat!(
            concat!(
                // aggregation_parameter
                "00000006",     // length
                "303132333435", // opaque data
            ),
            concat!(
                // partial_batch_selector
                "02",                                                               // query_type
                "0202020202020202020202020202020202020202020202020202020202020202", // batch_id
            ),
            concat!(
                // prepare_inits
                "00000076", // length
                concat!(
                    concat!(
                        // report_share
                        concat!(
                            // metadata
                            "0102030405060708090A0B0C0D0E0F10", // report_id
                            "000000000000D431",                 // time
                        ),
                        concat!(
                            // public_share
                            "00000000", // length
                            "",         // opaque data
                        ),
                        concat!(
                            // encrypted_input_share
                            "2A", // config_id
                            concat!(
                                // encapsulated_context
                                "0006",         // length
                                "303132333435", // opaque data
                            ),
                            concat!(
                                // payload
                                "00000006",     // length
                                "353433323130", // opaque data
                            ),
                        ),
                    ),
                    concat!(
                        // payload
                        "0000000b", // ping pong message length
                        "00",       // ping pong message type
                        concat!(
                            "00000006",     // prep_share length
                            "303132333435", // opaque data
                        )
                    ),
                ),
                concat!(
                    concat!(
                        concat!(
                            // metadata
                            "100F0E0D0C0B0A090807060504030201", // report_id
                            "0000000000011F46",                 // time
                        ),
                        concat!(
                            // public_share
                            "00000004", // length
                            "30313233", // opaque data
                        ),
                        concat!(
                            // encrypted_input_share
                            "0D", // config_id
                            concat!(
                                // encapsulated_context
                                "0004",     // length
                                "61626365", // opaque data
                            ),
                            concat!(
                                // payload
                                "00000004", // length
                                "61626664", // opaque data
                            ),
                        ),
                    ),
                    concat!(
                        // payload
                        "00000005", // ping pong message length
                        "02",       // ping pong message type
                        concat!(
                            "00000000", // length
                            "",         // opaque data
                        )
                    ),
                ),
            ),
        ),
    )])
}

#[test]
fn roundtrip_aggregation_job_continue_req() {
    roundtrip_encoding(&[(
        AggregationJobContinueReq {
            step: AggregationJobStep(42405),
            prepare_continues: Vec::from([
                PrepareContinue {
                    report_id: ReportId::from([
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    ]),
                    message: PingPongMessage::Initialize {
                        prep_share: Vec::from("012345"),
                    },
                },
                PrepareContinue {
                    report_id: ReportId::from([
                        16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                    ]),
                    message: PingPongMessage::Initialize {
                        prep_share: Vec::from("012345"),
                    },
                },
            ]),
        },
        concat!(
            "A5A5", // step
            concat!(
                // prepare_steps
                "0000003e", // length
                concat!(
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    concat!(
                        // payload
                        "0000000b", // ping pong message length
                        "00",       // ping pong message type
                        concat!(
                            "00000006",     // prep_share length
                            "303132333435", // opaque data
                        )
                    ),
                ),
                concat!(
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    concat!(
                        // payload
                        "0000000b", // ping pong message length
                        "00",       // ping pong message type
                        concat!(
                            "00000006",     // prep_share length
                            "303132333435", // opaque data
                        )
                    ),
                )
            ),
        ),
    )])
}

#[test]
fn roundtrip_aggregation_job_resp() {
    roundtrip_encoding(&[(
        AggregationJobResp {
            prepare_resps: Vec::from([
                PrepareResp {
                    report_id: ReportId::from([
                        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    ]),
                    result: PrepareStepResult::Continue {
                        message: PingPongMessage::Continue {
                            prep_msg: Vec::from("01234"),
                            prep_share: Vec::from("56789"),
                        },
                    },
                },
                PrepareResp {
                    report_id: ReportId::from([
                        16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                    ]),
                    result: PrepareStepResult::Finished,
                },
            ]),
        },
        concat!(concat!(
            // prepare_steps
            "00000039", // length
            concat!(
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "00",                               // prepare_step_result
                concat!(
                    "00000013", // ping pong message length
                    "01",       // ping pong message type
                    concat!(
                        // prep_msg
                        "00000005",   // prep_msg length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // prep_share
                        "00000005",   // prep_share length
                        "3536373839", // opaque data
                    )
                ),
            ),
            concat!(
                "100F0E0D0C0B0A090807060504030201", // report_id
                "01",                               // prepare_step_result
            )
        ),),
    )])
}

#[test]
fn roundtrip_batch_selector() {
    // TimeInterval.
    roundtrip_encoding(&[
        (
            BatchSelector::<TimeInterval> {
                batch_identifier: Interval::new(
                    Time::from_seconds_since_epoch(54321),
                    Duration::from_seconds(12345),
                )
                .unwrap(),
            },
            concat!(
                "01", // query_type
                concat!(
                    // batch_interval
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
        ),
        (
            BatchSelector::<TimeInterval> {
                batch_identifier: Interval::new(
                    Time::from_seconds_since_epoch(50821),
                    Duration::from_seconds(84354),
                )
                .unwrap(),
            },
            concat!(
                "01", // query_type
                concat!(
                    // batch_interval
                    "000000000000C685", // start
                    "0000000000014982", // duration
                ),
            ),
        ),
    ]);

    // FixedSize.
    roundtrip_encoding(&[
        (
            BatchSelector::<FixedSize> {
                batch_identifier: BatchId::from([12u8; 32]),
            },
            concat!(
                // batch_selector
                "02",                                                               // query_type
                "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // batch_id
            ),
        ),
        (
            BatchSelector::<FixedSize> {
                batch_identifier: BatchId::from([7u8; 32]),
            },
            concat!(
                "02",                                                               // query_type
                "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
            ),
        ),
    ])
}

#[test]
fn roundtrip_aggregate_share_req() {
    // TimeInterval.
    roundtrip_encoding(&[
        (
            AggregateShareReq::<TimeInterval> {
                batch_selector: BatchSelector {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(54321),
                        Duration::from_seconds(12345),
                    )
                    .unwrap(),
                },
                aggregation_parameter: Vec::new(),
                report_count: 439,
                checksum: ReportIdChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
            },
            concat!(
                concat!(
                    // batch_selector
                    "01", // query_type
                    concat!(
                        // batch_interval
                        "000000000000D431", // start
                        "0000000000003039", // duration
                    ),
                ),
                concat!(
                    // aggregation_parameter
                    "00000000", // length
                    "",         // opaque data
                ),
                "00000000000001B7", // report_count
                "0000000000000000000000000000000000000000000000000000000000000000", // checksum
            ),
        ),
        (
            AggregateShareReq::<TimeInterval> {
                batch_selector: BatchSelector {
                    batch_identifier: Interval::new(
                        Time::from_seconds_since_epoch(50821),
                        Duration::from_seconds(84354),
                    )
                    .unwrap(),
                },
                aggregation_parameter: Vec::from("012345"),
                report_count: 8725,
                checksum: ReportIdChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
            },
            concat!(
                concat!(
                    // batch_selector
                    "01", // query_type
                    concat!(
                        // batch_interval
                        "000000000000C685", // start
                        "0000000000014982", // duration
                    ),
                ),
                concat!(
                    // aggregation_parameter
                    "00000006",     // length
                    "303132333435", // opaque data
                ),
                "0000000000002215", // report_count
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
            ),
        ),
    ]);

    // FixedSize.
    roundtrip_encoding(&[
        (
            AggregateShareReq::<FixedSize> {
                batch_selector: BatchSelector {
                    batch_identifier: BatchId::from([12u8; 32]),
                },
                aggregation_parameter: Vec::new(),
                report_count: 439,
                checksum: ReportIdChecksum::get_decoded(&[u8::MIN; 32]).unwrap(),
            },
            concat!(
                concat!(
                    // batch_selector
                    "02", // query_type
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // batch_id
                ),
                concat!(
                    // aggregation_parameter
                    "00000000", // length
                    "",         // opaque data
                ),
                "00000000000001B7", // report_count
                "0000000000000000000000000000000000000000000000000000000000000000", // checksum
            ),
        ),
        (
            AggregateShareReq::<FixedSize> {
                batch_selector: BatchSelector {
                    batch_identifier: BatchId::from([7u8; 32]),
                },
                aggregation_parameter: Vec::from("012345"),
                report_count: 8725,
                checksum: ReportIdChecksum::get_decoded(&[u8::MAX; 32]).unwrap(),
            },
            concat!(
                concat!(
                    // batch_selector
                    "02", // query_type
                    "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
                ),
                concat!(
                    // aggregation_parameter
                    "00000006",     // length
                    "303132333435", // opaque data
                ),
                "0000000000002215", // report_count
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // checksum
            ),
        ),
    ]);
}

#[test]
fn roundtrip_aggregate_share() {
    roundtrip_encoding(&[
        (
            AggregateShare {
                encrypted_aggregate_share: HpkeCiphertext::new(
                    HpkeConfigId::from(10),
                    Vec::from("0123"),
                    Vec::from("4567"),
                ),
            },
            concat!(concat!(
                // encrypted_aggregate_share
                "0A", // config_id
                concat!(
                    // encapsulated_context
                    "0004",     // length
                    "30313233", // opaque data
                ),
                concat!(
                    // payload
                    "00000004", // length
                    "34353637", // opaque data
                ),
            )),
        ),
        (
            AggregateShare {
                encrypted_aggregate_share: HpkeCiphertext::new(
                    HpkeConfigId::from(12),
                    Vec::from("01234"),
                    Vec::from("567"),
                ),
            },
            concat!(concat!(
                // encrypted_aggregate_share
                "0C", // config_id
                concat!(
                    // encapsulated_context
                    "0005",       // length
                    "3031323334", // opaque data
                ),
                concat!(
                    "00000003", // length
                    "353637",   // opaque data
                ),
            )),
        ),
    ])
}

#[test]
fn roundtrip_input_share_aad() {
    roundtrip_encoding(&[(
        InputShareAad {
            task_id: TaskId::from([12u8; 32]),
            metadata: ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(54321),
            ),
            public_share: Vec::from("0123"),
        },
        concat!(
            "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
            concat!(
                // metadata
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "000000000000D431",                 // time
            ),
            concat!(
                // public_share
                "00000004", // length
                "30313233", // opaque data
            ),
        ),
    )])
}

#[test]
fn roundtrip_aggregate_share_aad() {
    // TimeInterval.
    roundtrip_encoding(&[(
        AggregateShareAad::<TimeInterval> {
            task_id: TaskId::from([12u8; 32]),
            aggregation_parameter: Vec::from([0, 1, 2, 3]),
            batch_selector: BatchSelector {
                batch_identifier: Interval::new(
                    Time::from_seconds_since_epoch(54321),
                    Duration::from_seconds(12345),
                )
                .unwrap(),
            },
        },
        concat!(
            "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
            concat!(
                // aggregation_parameter
                "00000004", // length
                "00010203", //opaque data
            ),
            concat!(
                // batch_selector
                "01", // query_type
                concat!(
                    // batch_interval
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
        ),
    )]);

    // FixedSize.
    roundtrip_encoding(&[(
        AggregateShareAad::<FixedSize> {
            task_id: TaskId::from([u8::MIN; 32]),
            aggregation_parameter: Vec::from([3, 2, 1, 0]),
            batch_selector: BatchSelector {
                batch_identifier: BatchId::from([7u8; 32]),
            },
        },
        concat!(
            "0000000000000000000000000000000000000000000000000000000000000000", // task_id
            concat!(
                // aggregation_parameter
                "00000004", // length
                "03020100", //opaque data
            ),
            concat!(
                // batch_selector
                "02",                                                               // query_type
                "0707070707070707070707070707070707070707070707070707070707070707", // batch_id
            ),
        ),
    )])
}

#[test]
fn taskid_serde() {
    assert_tokens(
        &TaskId::from([0; 32]),
        &[Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
    );
    assert_de_tokens_error::<TaskId>(
        &[Token::Str("/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
        "invalid base64url value",
    );
    assert_de_tokens_error::<TaskId>(
        &[Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
        "byte slice has incorrect length for TaskId",
    );
    assert_de_tokens_error::<TaskId>(
        &[Token::Str("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
        "byte slice has incorrect length for TaskId",
    );
}

#[test]
fn hpke_public_key_serde() {
    assert_tokens(
        &HpkePublicKey::from(Vec::from([1, 2, 3, 4])),
        &[Token::Str("AQIDBA")],
    );
    assert_de_tokens_error::<HpkePublicKey>(&[Token::Str("/AAAA")], "invalid base64url value");
}
