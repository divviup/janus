use crate::{
    Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, InputShareAad, PlaintextInputShare,
    Report, ReportError, ReportId, ReportMetadata, ReportUploadStatus, TaskId, Time, UploadRequest,
    UploadResponse, roundtrip_encoding, roundtrip_encoding_parameterized,
};
use prio::codec::Encode;

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
            Extension::new(ExtensionType::Taskbind, Vec::from("0123")),
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
    roundtrip_encoding(&[
        (ExtensionType::Tbd, "0000"),
        (ExtensionType::Taskbind, "FF00"),
    ])
}

#[test]
fn roundtrip_report_metadata() {
    roundtrip_encoding(&[
        (
            ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(12345),
                Vec::new(),
            ),
            concat!(
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "0000000000003039",                 // time
                concat!(
                    // public_extensions
                    "0000", // length
                ),
            ),
        ),
        (
            ReportMetadata::new(
                ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                Time::from_seconds_since_epoch(54321),
                Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
            ),
            concat!(
                "100F0E0D0C0B0A090807060504030201", // report_id
                "000000000000D431",                 // time
                concat!(
                    // public_extensions
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
                    // private_extensions
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
                    // private_extensions
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
                    Vec::new(),
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
                    concat!(
                        // public_extensions
                        "0000", // length
                    ),
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
                    Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
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
                    concat!(
                        // public_extensions
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
fn roundtrip_input_share_aad() {
    roundtrip_encoding(&[(
        InputShareAad {
            task_id: TaskId::from([12u8; 32]),
            metadata: ReportMetadata::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                Time::from_seconds_since_epoch(54321),
                Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
            ),
            public_share: Vec::from("0123"),
        },
        concat!(
            "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C", // task_id
            concat!(
                // metadata
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "000000000000D431",                 // time
                concat!(
                    // public_extensions
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
fn upload_response_size() {
    let response = UploadResponse::new(&[
        ReportUploadStatus::new(ReportId::from([0u8; 16]), ReportError::TaskExpired),
        ReportUploadStatus::new(ReportId::from([1u8; 16]), ReportError::InvalidMessage),
    ]);
    assert_eq!(response.encoded_len(), Some(34));
}

#[test]
fn roundtrip_upload_request() {
    roundtrip_encoding_parameterized(&[
        (UploadRequest::new(vec![]), 0, ""),
        {
            let val = UploadRequest::new(vec![Report::new(
                ReportMetadata::new(
                    ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    Time::from_seconds_since_epoch(54321),
                    Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                ),
                Vec::from("3210"),
                HpkeCiphertext::new(
                    HpkeConfigId::from(42),
                    Vec::from("012345"),
                    Vec::from("543210"),
                ),
                HpkeCiphertext::new(HpkeConfigId::from(13), Vec::from("abce"), Vec::from("abfd")),
            )]);
            let hex = concat!(
                concat!(
                    // metadata
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "000000000000D431",                 // time
                    concat!(
                        // public_extensions
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
            );
            (val, hex.len() / 2, hex)
        },
        {
            let val = UploadRequest::new(vec![
                Report::new(
                    ReportMetadata::new(
                        ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                        Time::from_seconds_since_epoch(12345),
                        Vec::new(),
                    ),
                    Vec::new(),
                    HpkeCiphertext::new(HpkeConfigId::from(10), Vec::from("abc"), Vec::from("def")),
                    HpkeCiphertext::new(HpkeConfigId::from(20), Vec::from("xyz"), Vec::from("uvw")),
                ),
                Report::new(
                    ReportMetadata::new(
                        ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                        Time::from_seconds_since_epoch(54321),
                        Vec::new(),
                    ),
                    Vec::new(),
                    HpkeCiphertext::new(HpkeConfigId::from(30), Vec::from("123"), Vec::from("456")),
                    HpkeCiphertext::new(HpkeConfigId::from(40), Vec::from("789"), Vec::from("012")),
                ),
            ]);
            let hex = concat!(
                // First report
                concat!(
                    // metadata
                    "0102030405060708090A0B0C0D0E0F10", // report_id
                    "0000000000003039",                 // time
                    concat!(
                        // public_extensions
                        "0000", // length
                    ),
                ),
                concat!(
                    // public_share
                    "00000000", // length
                ),
                concat!(
                    // leader_encrypted_input_share
                    "0A", // config_id
                    concat!(
                        // encapsulated_context
                        "0003",   // length
                        "616263", // "abc"
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "646566",   // "def"
                    ),
                ),
                concat!(
                    // helper_encrypted_input_share
                    "14", // config_id = 20
                    concat!(
                        // encapsulated_context
                        "0003",   // length
                        "78797A", // "xyz"
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "757677",   // "uvw"
                    ),
                ),
                // Second report
                concat!(
                    // metadata
                    "100F0E0D0C0B0A090807060504030201", // report_id
                    "000000000000D431",                 // time
                    concat!(
                        // public_extensions
                        "0000", // length
                    ),
                ),
                concat!(
                    // public_share
                    "00000000", // length
                ),
                concat!(
                    // leader_encrypted_input_share
                    "1E", // config_id = 30
                    concat!(
                        // encapsulated_context
                        "0003",   // length
                        "313233", // "123"
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "343536",   // "456"
                    ),
                ),
                concat!(
                    // helper_encrypted_input_share
                    "28", // config_id = 40
                    concat!(
                        // encapsulated_context
                        "0003",   // length
                        "373839", // "789"
                    ),
                    concat!(
                        // payload
                        "00000003", // length
                        "303132",   // "012"
                    ),
                ),
            );
            (val, hex.len() / 2, hex)
        },
    ]);
}

#[test]
fn roundtrip_upload_response() {
    roundtrip_encoding_parameterized(&[
        (UploadResponse::new(&[]), 0, ""),
        (
            UploadResponse::new(&[ReportUploadStatus::new(
                ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                ReportError::TaskExpired,
            )]),
            17,
            concat!(
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "07",                               // error = TaskExpired (7)
            ),
        ),
        (
            UploadResponse::new(&[
                ReportUploadStatus::new(
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    ReportError::TaskExpired,
                ),
                ReportUploadStatus::new(
                    ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                    ReportError::InvalidMessage,
                ),
                ReportUploadStatus::new(ReportId::from([0u8; 16]), ReportError::HpkeDecryptError),
            ]),
            17 * 3,
            concat!(
                // First failure
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "07",                               // error = TaskExpired (7)
                // Second failure
                "100F0E0D0C0B0A090807060504030201", // report_id
                "08",                               // error = InvalidMessage (8)
                // Third failure
                "00000000000000000000000000000000", // report_id
                "05",                               // error = HpkeDecryptError (5)
            ),
        ),
    ]);
}
