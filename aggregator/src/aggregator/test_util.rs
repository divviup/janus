use crate::{aggregator::Config, binaries::aggregator::parse_pem_ec_private_key};
use janus_aggregator_core::{
    datastore::{models::TaskAggregationCounter, Datastore},
    task::AggregatorTask,
};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    time::MockClock,
    vdaf::VdafInstance,
};
use janus_messages::{
    Extension, HpkeConfig, InputShareAad, PlaintextInputShare, Report, ReportId, ReportMetadata,
    ReportShare, Role, TaskId, Time,
};
use prio::{
    codec::Encode,
    vdaf::{self, prio3::Prio3Count, Client},
};
use rand::random;
use ring::signature::EcdsaKeyPair;
use std::time::Duration;
use tokio::time::{sleep, Instant};

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

pub fn hpke_config_verification_key() -> ring::signature::UnparsedPublicKey<Vec<u8>> {
    use ring::signature::{KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
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
) -> Report {
    assert_eq!(task.vdaf(), &VdafInstance::Prio3Count);

    let vdaf = Prio3Count::new_count(2).unwrap();
    let report_metadata = ReportMetadata::new(id, report_timestamp);

    let (public_share, measurements) = vdaf.shard(&true, id.as_ref()).unwrap();

    let associated_data = InputShareAad::new(
        *task.id(),
        report_metadata.clone(),
        public_share.get_encoded().unwrap(),
    );

    let leader_ciphertext = hpke::seal(
        hpke_keypair.config(),
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Leader),
        &PlaintextInputShare::new(Vec::new(), measurements[0].get_encoded().unwrap())
            .get_encoded()
            .unwrap(),
        &associated_data.get_encoded().unwrap(),
    )
    .unwrap();
    let helper_ciphertext = hpke::seal(
        hpke_keypair.config(),
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
        &PlaintextInputShare::new(Vec::new(), measurements[1].get_encoded().unwrap())
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
    create_report_custom(task, report_timestamp, random(), hpke_keypair)
}

pub fn generate_helper_report_share<V: vdaf::Client<16>>(
    task_id: TaskId,
    report_metadata: ReportMetadata,
    cfg: &HpkeConfig,
    public_share: &V::PublicShare,
    extensions: Vec<Extension>,
    input_share: &V::InputShare,
) -> ReportShare {
    generate_helper_report_share_for_plaintext(
        report_metadata.clone(),
        cfg,
        public_share.get_encoded().unwrap(),
        &PlaintextInputShare::new(extensions, input_share.get_encoded().unwrap())
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

    let end_instant = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        let counters = datastore
            .run_unnamed_tx(|tx| {
                Box::pin(async move {
                    Ok(tx
                        .get_task_aggregation_counter(&task_id)
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
