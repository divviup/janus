use crate::{aggregator::Config, binaries::aggregator::parse_pem_ec_private_key};
use aws_lc_rs::signature::EcdsaKeyPair;
use janus_aggregator_core::{
    datastore::{Datastore, task_counters::TaskAggregationCounter},
    task::AggregatorTask,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    time::MockClock,
    vdaf::{VdafInstance, vdaf_application_context},
};
use janus_messages::{
    AggregateShare, Extension, HpkeCiphertext, HpkeConfig, HpkeConfigId, InputShareAad,
    PlaintextInputShare, Report, ReportId, ReportMetadata, ReportShare, Role, TaskId, Time,
};
use prio::{
    codec::Encode,
    vdaf::{self, Client, prio3::Prio3Count},
};
use rand::random;
use std::time::Duration;
use tokio::time::{Instant, sleep};

pub(crate) const BATCH_AGGREGATION_SHARD_COUNT: u64 = 32;

pub const TASK_AGGREGATION_COUNTER_SHARD_COUNT: u64 = 16;

/// HPKE config signing key for use in tests.
///
/// This key is "testECCP256", a standard test key taken from [RFC
/// 9500](https://www.rfc-editor.org/rfc/rfc9500.html#name-ecdlp-keys). Boilerplate: this is a
/// non-sensitive test key, so it is OK that it is checked into a public GitHub repository.
/// Given that this key is public, it should not be used for any sensitive purpose.
pub(crate) const HPKE_CONFIG_SIGNING_KEY_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObLW92AqkWunJXowVR2Z5/+yVPBaFHnEedDk5WJxk/BoAoGCCqGSM49
AwEHoUQDQgAEQiVI+I+3gv+17KN0RFLHKh5Vj71vc75eSOkyMsxFxbFsTNEMTLjV
uKFxOelIgsiZJXKZNCX0FBmrfpCkKklCcg==
-----END EC PRIVATE KEY-----";

pub(crate) fn hpke_config_signing_key() -> EcdsaKeyPair {
    // ring's EcdsaKeyPair does not implement Clone, so we instead store the serialized key &
    // parse it each time.
    parse_pem_ec_private_key(HPKE_CONFIG_SIGNING_KEY_PEM).unwrap()
}

pub fn hpke_config_verification_key() -> aws_lc_rs::signature::UnparsedPublicKey<Vec<u8>> {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, KeyPair, UnparsedPublicKey};
    UnparsedPublicKey::new(
        &ECDSA_P256_SHA256_ASN1,
        hpke_config_signing_key().public_key().as_ref().to_vec(),
    )
}

pub(crate) fn default_aggregator_config() -> Config {
    // Enable upload write batching & batch aggregation sharding by default, in hopes that we
    // can shake out any bugs.
    Config {
        max_upload_batch_size: 5,
        max_upload_batch_write_delay: Duration::from_millis(100),
        batch_aggregation_shard_count: BATCH_AGGREGATION_SHARD_COUNT,
        hpke_config_signing_key: Some(hpke_config_signing_key()),
        ..Default::default()
    }
}

pub fn create_report_custom(
    task: &AggregatorTask,
    report_timestamp: Time,
    id: ReportId,
    hpke_keypair: &HpkeKeypair,
    public_extensions: Vec<Extension>,
    leader_extensions: Vec<Extension>,
    helper_extensions: Vec<Extension>,
) -> Report {
    assert_eq!(task.vdaf(), &VdafInstance::Prio3Count);

    let vdaf = Prio3Count::new_count(2).unwrap();
    let report_metadata = ReportMetadata::new(id, report_timestamp, public_extensions);

    let (public_share, measurements) = vdaf
        .shard(&vdaf_application_context(task.id()), &true, id.as_ref())
        .unwrap();

    let associated_data = InputShareAad::new(
        *task.id(),
        report_metadata.clone(),
        public_share.get_encoded().unwrap(),
    );

    let leader_ciphertext = hpke::seal(
        hpke_keypair.config(),
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
        &PlaintextInputShare::new(leader_extensions, measurements[0].get_encoded().unwrap())
            .get_encoded()
            .unwrap(),
        &associated_data.get_encoded().unwrap(),
    )
    .unwrap();
    let helper_ciphertext = hpke::seal(
        hpke_keypair.config(),
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
        &PlaintextInputShare::new(helper_extensions, measurements[1].get_encoded().unwrap())
            .get_encoded()
            .unwrap(),
        &associated_data.get_encoded().unwrap(),
    )
    .unwrap();

    Report::new(
        report_metadata,
        public_share.get_encoded().unwrap(),
        leader_ciphertext,
        helper_ciphertext,
    )
}

pub fn create_report(
    task: &AggregatorTask,
    hpke_keypair: &HpkeKeypair,
    report_timestamp: Time,
) -> Report {
    create_report_custom(
        task,
        report_timestamp,
        random(),
        hpke_keypair,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

pub fn generate_helper_report_share<V: vdaf::Client<16>>(
    task_id: TaskId,
    report_metadata: ReportMetadata,
    cfg: &HpkeConfig,
    public_share: &V::PublicShare,
    private_extensions: Vec<Extension>,
    input_share: &V::InputShare,
) -> ReportShare {
    generate_helper_report_share_for_plaintext(
        report_metadata.clone(),
        cfg,
        public_share.get_encoded().unwrap(),
        &PlaintextInputShare::new(private_extensions, input_share.get_encoded().unwrap())
            .get_encoded()
            .unwrap(),
        &InputShareAad::new(
            task_id,
            report_metadata,
            public_share.get_encoded().unwrap(),
        )
        .get_encoded()
        .unwrap(),
    )
}

pub fn generate_helper_report_share_for_plaintext(
    metadata: ReportMetadata,
    cfg: &HpkeConfig,
    encoded_public_share: Vec<u8>,
    plaintext: &[u8],
    associated_data: &[u8],
) -> ReportShare {
    ReportShare::new(
        metadata,
        encoded_public_share,
        hpke::seal(
            cfg,
            &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
            plaintext,
            associated_data,
        )
        .unwrap(),
    )
}

pub async fn assert_task_aggregation_counter(
    datastore: &Datastore<MockClock>,
    task_id: TaskId,
    expected_counters: TaskAggregationCounter,
) {
    // We can't coordinate with the counter-update tasks, so we loop on polling them.

    sleep(Duration::from_millis(100)).await;

    let end_instant = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        let counters = datastore
            .run_unnamed_tx(|tx| {
                Box::pin(async move {
                    Ok(TaskAggregationCounter::load(tx, &task_id)
                        .await
                        .unwrap()
                        .unwrap())
                })
            })
            .await
            .unwrap();

        if counters == expected_counters {
            return;
        }
        if now > end_instant {
            // Last chance: assert equality; this will likely fail, but the error message will
            // provide hopefully-useful information to the caller.
            assert_eq!(counters, expected_counters);
        }
        sleep(Duration::from_millis(100)).await;
    }
}

pub fn fake_aggregate_share() -> AggregateShare {
    AggregateShare::new(HpkeCiphertext::new(
        HpkeConfigId::from(100),
        Vec::new(),
        Vec::new(),
    ))
}
