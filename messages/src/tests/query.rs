use crate::{
    query_type, roundtrip_encoding, BatchId, Duration, FixedSize, FixedSizeQuery, Interval, Query,
    TaskId, Time, TimeInterval,
};

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
fn roundtrip_code() {
    roundtrip_encoding(&[
        (query_type::Code::Reserved, "00"),
        (query_type::Code::TimeInterval, "01"),
        (query_type::Code::FixedSize, "02"),
    ])
}
