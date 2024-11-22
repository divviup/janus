use crate::{
    roundtrip_encoding, AggregateShare, AggregateShareAad, AggregateShareReq, BatchId,
    BatchSelector, Collection, CollectionReq, Duration, HpkeCiphertext, HpkeConfigId, Interval,
    LeaderSelected, PartialBatchSelector, Query, ReportIdChecksum, TaskId, Time, TimeInterval,
};
use prio::codec::Decode;

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
                    "01",   // batch_mode
                    "0010", // length
                    concat!(
                        // opaque data
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
                    "01",   // batch_mode
                    "0010", // length
                    concat!(
                        // query body
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

    // LeaderSelected.
    roundtrip_encoding(&[
        (
            CollectionReq::<LeaderSelected> {
                query: Query { query_body: () },
                aggregation_parameter: Vec::new(),
            },
            concat!(
                concat!(
                    "02",   // batch_mode
                    "0000", // length
                    "",     // opaque data
                ),
                concat!(
                    // aggregation_parameter
                    "00000000", // length
                    "",         // opaque data
                ),
            ),
        ),
        (
            CollectionReq::<LeaderSelected> {
                query: Query { query_body: () },
                aggregation_parameter: Vec::from("012345"),
            },
            concat!(
                concat!(
                    "02",   // batch_mode
                    "0000", // length
                    "",     // opaque data
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
            "01",   // batch_mode
            "0000", // length
            "",     // opaque data
        ),
    )]);

    // LeaderSelected.
    roundtrip_encoding(&[
        (
            PartialBatchSelector::new_leader_selected(BatchId::from([3u8; 32])),
            concat!(
                "02",                                                               // batch_mode
                "0020",                                                             // length
                "0303030303030303030303030303030303030303030303030303030303030303", // opaque data
            ),
        ),
        (
            PartialBatchSelector::new_leader_selected(BatchId::from([4u8; 32])),
            concat!(
                "02",                                                               // batch_mode
                "0020",                                                             // length
                "0404040404040404040404040404040404040404040404040404040404040404", // opaque data
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
                    "01",   // batch_mode
                    "0000", // length
                    "",     // opaque data
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
                    "01",   // batch_mode
                    "0000", // length
                    "",     // opaque data
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

    // LeaderSelected.
    roundtrip_encoding(&[
        (
            Collection {
                partial_batch_selector: PartialBatchSelector::new_leader_selected(BatchId::from(
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
                    "02",   // batch_mode
                    "0020", // length
                    "0303030303030303030303030303030303030303030303030303030303030303", // opaque data
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
                partial_batch_selector: PartialBatchSelector::new_leader_selected(BatchId::from(
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
                    "02",   // batch_mode
                    "0020", // length
                    "0404040404040404040404040404040404040404040404040404040404040404", // opaque data
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
                "01",   // batch_mode
                "0010", // length
                concat!(
                    // opaque data
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
                "01",   // batch_mode
                "0010", // length
                concat!(
                    // opaque data
                    "000000000000C685", // start
                    "0000000000014982", // duration
                ),
            ),
        ),
    ]);

    // LeaderSelected.
    roundtrip_encoding(&[
        (
            BatchSelector::<LeaderSelected> {
                batch_identifier: BatchId::from([12u8; 32]),
            },
            concat!(
                // batch_selector
                "02",                                                               // batch_mode
                "0020",                                                             // length
                "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // opaque data
            ),
        ),
        (
            BatchSelector::<LeaderSelected> {
                batch_identifier: BatchId::from([7u8; 32]),
            },
            concat!(
                "02",                                                               // batch_mode
                "0020",                                                             // length
                "0707070707070707070707070707070707070707070707070707070707070707", // opaque data
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
                    "01",   // batch_mode
                    "0010", // length
                    concat!(
                        // opaque data
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
                    "01",   // batch_mode
                    "0010", // length
                    concat!(
                        // opaque data
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

    // LeaderSelected.
    roundtrip_encoding(&[
        (
            AggregateShareReq::<LeaderSelected> {
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
                    "02",   // batch_mode
                    "0020", // length
                    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // opaque data
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
            AggregateShareReq::<LeaderSelected> {
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
                    "02",   // batch_mode
                    "0020", // length
                    "0707070707070707070707070707070707070707070707070707070707070707", // opaque data
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
                "01",   // batch_mode
                "0010", // length
                concat!(
                    // opaque data
                    "000000000000D431", // start
                    "0000000000003039", // duration
                ),
            ),
        ),
    )]);

    // LeaderSelected.
    roundtrip_encoding(&[(
        AggregateShareAad::<LeaderSelected> {
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
                "02",                                                               // batch_mode
                "0020",                                                             // length
                "0707070707070707070707070707070707070707070707070707070707070707", // opaque data
            ),
        ),
    )])
}
