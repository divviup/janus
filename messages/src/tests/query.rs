use crate::{
    BatchId, Duration, Interval, LeaderSelected, Query, TaskId, Time, TimeInterval, batch_mode,
    roundtrip_encoding,
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
            Query::<TimeInterval> {
                query_body: Interval::new(
                    Time::from_seconds_since_epoch(48913),
                    Duration::from_seconds(44721),
                )
                .unwrap(),
            },
            concat!(
                "01",   // batch_mode
                "0010", // length
                concat!(
                    // opaque data
                    "000000000000BF11", // start
                    "000000000000AEB1", // duration
                ),
            ),
        ),
    ]);

    // LeaderSelected.
    roundtrip_encoding(&[(
        Query::<LeaderSelected> { query_body: () },
        concat!(
            "02",   // batch_mode
            "0000", // length
            "",     // opaque data
        ),
    )])
}

#[test]
fn roundtrip_code() {
    roundtrip_encoding(&[
        (batch_mode::Code::Reserved, "00"),
        (batch_mode::Code::TimeInterval, "01"),
        (batch_mode::Code::LeaderSelected, "02"),
    ])
}
