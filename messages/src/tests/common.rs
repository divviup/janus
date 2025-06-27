use crate::{Duration, Interval, Role, TaskId, Time, Url, roundtrip_encoding};
use assert_matches::assert_matches;
use prio::codec::{CodecError, Decode, Encode};
use serde_test::{Token, assert_de_tokens_error, assert_tokens};

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
        Url::get_decoded(&hex::decode("0000").unwrap()),
        Err(CodecError::Other(_))
    );

    // Non-ascii string
    assert_matches!(
        Url::get_decoded(&hex::decode("0001FF").unwrap()),
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
fn roundtrip_role() {
    roundtrip_encoding(&[
        (Role::Collector, "00"),
        (Role::Client, "01"),
        (Role::Leader, "02"),
        (Role::Helper, "03"),
    ]);
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
