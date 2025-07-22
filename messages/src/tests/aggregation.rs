use crate::{
    AggregationJobContinueReq, AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep,
    BatchId, Extension, ExtensionType, HpkeCiphertext, HpkeConfigId, LeaderSelected,
    PartialBatchSelector, PrepareContinue, PrepareInit, PrepareResp, PrepareStepResult,
    ReportError, ReportId, ReportMetadata, ReportShare, Time, roundtrip_encoding,
};
use prio::topology::ping_pong::PingPongMessage;

#[test]
fn roundtrip_report_share() {
    roundtrip_encoding(&[
        (
            ReportShare {
                metadata: ReportMetadata::new(
                    ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                    Time::from_seconds_since_epoch(54321),
                    Vec::new(),
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
                    concat!(
                        // public_extensions
                        "0000", // length
                    ),
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
                    Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
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
                        Vec::new(),
                    ),
                    public_share: Vec::new(),
                    encrypted_input_share: HpkeCiphertext::new(
                        HpkeConfigId::from(42),
                        Vec::from("012345"),
                        Vec::from("543210"),
                    ),
                },
                message: PingPongMessage::Initialize {
                    prepare_share: Vec::from("012345"),
                },
            },
            concat!(
                concat!(
                    // report_share
                    concat!(
                        // metadata
                        "0102030405060708090A0B0C0D0E0F10", // report_id
                        "000000000000D431",                 // time
                        concat!(
                            // public_extensions
                            "0000", // length
                        ),
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
                        "00000006",     // prepare_share length
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
                        Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                    ),
                    public_share: Vec::from("0123"),
                    encrypted_input_share: HpkeCiphertext::new(
                        HpkeConfigId::from(13),
                        Vec::from("abce"),
                        Vec::from("abfd"),
                    ),
                },
                message: PingPongMessage::Finish {
                    prepare_message: Vec::new(),
                },
            },
            concat!(
                concat!(
                    // report_share
                    concat!(
                        // metadata
                        "100F0E0D0C0B0A090807060504030201", // report_id
                        "0000000000011F46",                 // time
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
                        "00000000", // prepare_message length
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
                        prepare_message: Vec::from("012345"),
                        prepare_share: Vec::from("6789"),
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
                        "00000006",     // prepare_message length
                        "303132333435", // opaque data
                    ),
                    concat!(
                        "00000004", // prepare_share length
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
                result: PrepareStepResult::Reject(ReportError::VdafPrepError),
            },
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // report_id
                "02",                               // prepare_step_result
                "06",                               // report_share_error
            ),
        ),
    ])
}

#[test]
fn roundtrip_report_share_error() {
    roundtrip_encoding(&[
        (ReportError::Reserved, "00"),
        (ReportError::BatchCollected, "01"),
        (ReportError::ReportReplayed, "02"),
        (ReportError::ReportDropped, "03"),
        (ReportError::HpkeUnknownConfigId, "04"),
        (ReportError::HpkeDecryptError, "05"),
        (ReportError::VdafPrepError, "06"),
        (ReportError::TaskExpired, "07"),
        (ReportError::InvalidMessage, "08"),
        (ReportError::ReportTooEarly, "09"),
        (ReportError::TaskNotStarted, "0A"),
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
                            Vec::new(),
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    message: PingPongMessage::Initialize {
                        prepare_share: Vec::from("012345"),
                    },
                },
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            Time::from_seconds_since_epoch(73542),
                            Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                    message: PingPongMessage::Finish {
                        prepare_message: Vec::new(),
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
                "01",   // batch_mode
                "0000", // length
                "",     // opaque data
            ),
            concat!(
                // prepare_inits
                "00000082", // length
                concat!(
                    concat!(
                        // report_share
                        concat!(
                            // metadata
                            "0102030405060708090A0B0C0D0E0F10", // report_id
                            "000000000000D431",                 // time
                            concat!(
                                // public_extensions
                                "0000", // length
                            ),
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
                            "00000006",     // prepare_share length
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
                            "00000000", // prepare_message length
                            ""          // opaque data
                        )
                    )
                ),
            ),
        ),
    )]);

    // LeaderSelected.
    roundtrip_encoding(&[(
        AggregationJobInitializeReq::<LeaderSelected> {
            aggregation_parameter: Vec::from("012345"),
            partial_batch_selector: PartialBatchSelector::new_leader_selected(BatchId::from(
                [2u8; 32],
            )),
            prepare_inits: Vec::from([
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
                            Time::from_seconds_since_epoch(54321),
                            Vec::new(),
                        ),
                        public_share: Vec::new(),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(42),
                            Vec::from("012345"),
                            Vec::from("543210"),
                        ),
                    },
                    message: PingPongMessage::Initialize {
                        prepare_share: Vec::from("012345"),
                    },
                },
                PrepareInit {
                    report_share: ReportShare {
                        metadata: ReportMetadata::new(
                            ReportId::from([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]),
                            Time::from_seconds_since_epoch(73542),
                            Vec::from([Extension::new(ExtensionType::Tbd, Vec::from("0123"))]),
                        ),
                        public_share: Vec::from("0123"),
                        encrypted_input_share: HpkeCiphertext::new(
                            HpkeConfigId::from(13),
                            Vec::from("abce"),
                            Vec::from("abfd"),
                        ),
                    },
                    message: PingPongMessage::Finish {
                        prepare_message: Vec::new(),
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
                "02",                                                               // batch_mode
                "0020",                                                             // length
                "0202020202020202020202020202020202020202020202020202020202020202", // opaque data
            ),
            concat!(
                // prepare_inits
                "00000082", // length
                concat!(
                    concat!(
                        // report_share
                        concat!(
                            // metadata
                            "0102030405060708090A0B0C0D0E0F10", // report_id
                            "000000000000D431",                 // time
                            concat!(
                                // public_extensions
                                "0000", // length
                            ),
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
                            "00000006",     // prepare_share length
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
                        prepare_share: Vec::from("012345"),
                    },
                },
                PrepareContinue {
                    report_id: ReportId::from([
                        16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                    ]),
                    message: PingPongMessage::Initialize {
                        prepare_share: Vec::from("012345"),
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
                            "00000006",     // prepare_share length
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
                            "00000006",     // prepare_share length
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
                            prepare_message: Vec::from("01234"),
                            prepare_share: Vec::from("56789"),
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
        concat!(
            // prepare_steps
            "00000039", // length
            concat!(
                "0102030405060708090A0B0C0D0E0F10", // report_id
                "00",                               // prepare_step_result
                concat!(
                    "00000013", // ping pong message length
                    "01",       // ping pong message type
                    concat!(
                        // prepare_message
                        "00000005",   // prepare_message length
                        "3031323334", // opaque data
                    ),
                    concat!(
                        // prepare_share
                        "00000005",   // prepare_share length
                        "3536373839", // opaque data
                    )
                ),
            ),
            concat!(
                "100F0E0D0C0B0A090807060504030201", // report_id
                "01",                               // prepare_step_result
            )
        ),
    )])
}
