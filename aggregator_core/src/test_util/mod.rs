use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label},
    test_util::VdafTranscript,
};
use janus_messages::{
    Extension, HpkeConfig, InputShareAad, PlaintextInputShare, ReportMetadata, Role, TaskId,
};
use opentelemetry::metrics::{noop::NoopMeterProvider, Meter, MeterProvider as _};
use prio::{codec::Encode as _, vdaf};

use crate::datastore::models::LeaderStoredReport;

/// Returns a [`LeaderStoredReport`] with the given task ID & metadata values and encrypted
/// input shares corresponding to the given HPKE configs & input shares.
pub fn generate_report<const SEED_SIZE: usize, V>(
    task_id: TaskId,
    report_metadata: ReportMetadata,
    helper_hpke_config: &HpkeConfig,
    extensions: Vec<Extension>,
    transcript: &VdafTranscript<SEED_SIZE, V>,
) -> LeaderStoredReport<SEED_SIZE, V>
where
    V: vdaf::Aggregator<SEED_SIZE, 16> + vdaf::Client<16>,
{
    let encrypted_helper_input_share = hpke::seal(
        helper_hpke_config,
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
        &PlaintextInputShare::new(
            Vec::new(),
            transcript.helper_input_share.get_encoded().unwrap(),
        )
        .get_encoded()
        .unwrap(),
        &InputShareAad::new(
            task_id,
            report_metadata.clone(),
            transcript.public_share.get_encoded().unwrap(),
        )
        .get_encoded()
        .unwrap(),
    )
    .unwrap();

    LeaderStoredReport::new(
        task_id,
        report_metadata,
        transcript.public_share.clone(),
        extensions,
        transcript.leader_input_share.clone(),
        encrypted_helper_input_share,
    )
}

pub fn noop_meter() -> Meter {
    NoopMeterProvider::new().meter("janus_aggregator")
}
