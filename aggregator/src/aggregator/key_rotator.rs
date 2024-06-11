use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

#[allow(unused_imports)]
use crate::aggregator::Config as AggregatorConfig; // used in doccomment.
use crate::cache::GlobalHpkeKeypairCache;
use anyhow::{anyhow, Error};
use derivative::Derivative;
use futures::FutureExt;
use janus_aggregator_core::datastore::{
    models::{GlobalHpkeKeypair, HpkeKeyState},
    Datastore, Error as DatastoreError, Transaction,
};
use janus_core::{
    hpke::{generate_hpke_config_and_private_key, HpkeCiphersuite},
    time::{Clock, TimeExt},
};
use janus_messages::{Duration, HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId, Time};
use serde::{de, Deserialize, Deserializer, Serialize};
use tracing::{debug, info};

/// Handles key rotation for Janus, according to policies defined in the configuration.
///
/// # Global HPKE Keys
///
/// The key rotator can handle key rotation for global HPKE keys. It moves keys through a state
/// machine whose states are defined by [`HpkeKeyState`].
///
/// ## Manual Changes
///
/// The key rotator is tolerant of some manual operator changes to the `global_hpke_keys` table.
///
/// The easiest way to manually initiate a key rotation is to insert a new pending keypair into
/// the table using `janus_cli` or the aggregator API.
///
/// It is strongly discouraged to:
///   - Insert keypairs with ciphersuites that are not in the configuration, as they'll be deleted
///     immediately.
///   - Delete active or expired keypairs too early, as that would leave Janus unable to decrypt
///     report shares using the keypair.
///   - Promote pending keypairs too early, unless all Janus replicas have been rebooted since
///     their insertion.
///   - Directly insert active keypairs, since that could leave some Janus replicas unable to
///     decrypt incoming report shares.
///
/// Keypairs that are manually inserted are adopted by the key rotator and will have their lifecycle
/// managed. The key rotator keeps only one key per ciphersuite around, preferring to use the latest
/// inserted key.
#[derive(Debug)]
pub struct KeyRotator<C: Clock> {
    datastore: Arc<Datastore<C>>,
    hpke: HpkeKeyRotatorConfig,
}

/// Defines the ciphersuite and rotation policy of a global HPKE key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeKeyRotatorConfig {
    /// How long key remains in [`HpkeKeyState::Pending`] before being moved to
    /// [`HpkeKeyState::Active`]. This should be greater than
    /// [`AggregatorConfig::global_hpke_configs_refresh_interval`].
    #[serde(rename = "pending_duration_s", default = "default_pending_duration")]
    pub pending_duration: Duration,

    /// The time-to-live of the key. Once this is exceeded, the key is moved to
    /// [`HpkeKeyState::Expired`]. It is at operator discretion as to how long this should be.
    #[serde(rename = "active_duration_s", default = "default_active_duration")]
    pub active_duration: Duration,

    /// How long the key remains in [`HpkeKeyState::Expired`] before being deleted. This should
    /// be greater than the clients' HPKE key cache maximum age.
    #[serde(rename = "expired_duration_s", default = "default_expired_duration")]
    pub expired_duration: Duration,

    /// Set of keys to manage, identified by ciphersuite. Existing keys whose ciphersuites are not
    /// in this list are safely phased out.
    #[serde(default = "default_hpke_ciphersuites")]
    pub ciphersuites: HashSet<HpkeCiphersuite>,
}

impl<C: Clock> KeyRotator<C> {
    pub fn new(datastore: Arc<Datastore<C>>, hpke: HpkeKeyRotatorConfig) -> Self {
        Self { datastore, hpke }
    }

    /// Runs the key rotator.
    ///
    /// # Errors
    ///
    /// Errors on general datastore errors.
    ///
    /// This is not permissive of [`HpkeConfigId`] space exhaustion, i.e. if there are more rows
    /// than what fit into a `u8`, this process will error. To avoid this, keep the list of managed
    /// ciphersuites small, and the expiration duration less than the key age.
    #[tracing::instrument(err)]
    pub async fn run(&self) -> Result<(), Error> {
        self.datastore
            .run_tx("global_hpke_key_rotator", |tx| {
                let config = Arc::new(self.hpke.clone());
                Box::pin(async move { Self::run_hpke(tx, &config).await })
            })
            .await
            .map_err(|err| err.into())
    }

    #[tracing::instrument(err, skip(tx))]
    async fn run_hpke(
        tx: &Transaction<'_, C>,
        config: &HpkeKeyRotatorConfig,
    ) -> Result<(), DatastoreError> {
        // Take an ExclusiveLock on the table. This ensures that only one key rotator replica
        // writes to the table at a time and that each replica gets a consistent view of the table.
        //
        // ExclusiveLock does not conflict with the AccessShare lock taken by table reads, i.e.
        // other aggregator replicas can continue to refresh their key caches without being blocked.
        tx.lock_global_hpke_keypairs().await?;

        let hpke_key_rotator = HpkeKeyRotator::new(tx, config).await?;
        let ops = hpke_key_rotator.sweep()?;
        hpke_key_rotator.write(tx, &ops).await
    }
}

fn duration_since<C: Clock>(clock: &C, time: &Time) -> Duration {
    // Use saturating difference to account for time skew between key rotator runners. Since
    // key rotators are synchronized by an exclusive lock on the table, it's possible that
    // time skew between concurrently running replicas result in underflows.
    clock.now().saturating_difference(time)
}

/// In-memory representation of the `global_hpke_keys` table.
#[derive(Derivative)]
#[derivative(Debug)]
struct HpkeKeyRotator<'a, C: Clock> {
    clock: C,
    config: &'a HpkeKeyRotatorConfig,

    // Data structures for intermediate state.
    #[derivative(Debug = "ignore")]
    available_ids: Box<dyn Iterator<Item = HpkeConfigId> + Send + Sync>,
    keypairs: HashMap<HpkeConfigId, GlobalHpkeKeypair>,
    initially_empty: bool,
}

impl<'a, C: Clock> HpkeKeyRotator<'a, C> {
    async fn new(
        tx: &Transaction<'_, C>,
        config: &'a HpkeKeyRotatorConfig,
    ) -> Result<Self, DatastoreError> {
        let keypairs: HashMap<_, _> = tx
            .get_global_hpke_keypairs()
            .inspect(|keypairs| debug!(?keypairs, "table state before running key rotator"))
            .await?
            .into_iter()
            .map(|keypair| (*keypair.id(), keypair))
            .collect();

        let ids: HashSet<_> = keypairs.iter().map(|(&id, _)| u8::from(id)).collect();
        // Try to cycle through the entire u8 space before going back to zero. This allows us a
        // bigger window to quicky reject reports from faulty old clients with an outdated HPKE
        // config error, rather than attempting to decrypt them with the wrong key.
        let newest_id = keypairs
            .iter()
            .max_by_key(|(&id, _)| id)
            .map(|(&id, _)| id.into())
            .unwrap_or(0);
        let available_ids = Box::new((newest_id..=u8::MAX).chain(0..newest_id).filter_map(
            move |id| {
                if !ids.contains(&id) {
                    Some(HpkeConfigId::from(id))
                } else {
                    None
                }
            },
        ));

        Ok(Self {
            clock: tx.clock().clone(),
            initially_empty: keypairs.is_empty(),
            keypairs,
            available_ids,
            config,
        })
    }

    /// Returns the [`HpkeOp`]s necessary to move all keys into a compliant state.
    ///
    /// Key bootstrap policy:
    ///   - If this is the very first run of Janus, insert keypairs in [`HpkeKeyState::Active`]
    ///     for each configured ciphersuite. Detect first run by whether the `global_hpke_keys`
    ///     table is empty.
    ///   - For each configured ciphersuite, if there is no pending or active key, insert
    ///     a key in [`HpkeKeyState::Pending`].
    ///
    /// Rotation policy:
    ///   - If the key has been in [`HpkeKeyState::Expired`] for at least
    ///     [`HpkeKeyRotatorConfig::expired_duration`], delete it.
    ///   - If the key has a ciphersuite that is not known, safely phase it out. If the key is
    ///     in [`HpkeKeyState::Pending`], delete it immediately. If it is in
    ///     [`HpkeKeyState::Active`], move it to expired.
    ///   - For each configured ciphersuite, move the latest pending key to active if it has been
    ///     pending for at least [`HpkeKeyRotatorConfig::pending_duration`]. Delete other pending
    ///     keys.
    ///   - For each configured ciphersuite, if the active key has been active for more than
    ///     [`HpkeKeyRotatorConfig::active_duration`] and there is no pending key, insert a pending
    ///     key.
    ///   - For each configured ciphersuite, expire all but the newest active key.
    fn sweep(&self) -> Result<Vec<HpkeOp>, DatastoreError> {
        let mut ops: Vec<HpkeOp> = Vec::new();

        // Bootstrap new keys.
        for ciphersuite in &self.config.ciphersuites {
            if self.initially_empty {
                ops.push(HpkeOp::Create(
                    *ciphersuite,
                    HpkeKeyState::Active,
                    "bootstrapping new database",
                ));
            } else if !self.keypairs.values().any(|keypair| {
                &keypair.ciphersuite() == ciphersuite
                    && (keypair.is_active() || keypair.is_pending())
            }) {
                ops.push(HpkeOp::Create(
                    *ciphersuite,
                    HpkeKeyState::Pending,
                    "bootstrapping new configuration",
                ))
            }
        }

        // Partition existing keypairs by ciphersuite and state. The keypairs are sorted in
        // descending order by `last_state_change_at`, i.e. the latest is first.
        let mut by_ciphersuite: HashMap<
            HpkeCiphersuite,
            HashMap<HpkeKeyState, VecDeque<&GlobalHpkeKeypair>>,
        > = HashMap::new();
        for (_, keypair) in self.keypairs.iter() {
            by_ciphersuite
                .entry(keypair.ciphersuite())
                .and_modify(|by_state| {
                    by_state
                        .entry(*keypair.state())
                        .and_modify(|entry| {
                            entry.insert(
                                entry.partition_point(|&candidate| {
                                    candidate.last_state_change_at()
                                        > keypair.last_state_change_at()
                                }),
                                keypair,
                            )
                        })
                        .or_insert_with(|| VecDeque::from([keypair]));
                })
                .or_insert_with(|| HashMap::from([(*keypair.state(), VecDeque::from([keypair]))]));
        }

        for (ciphersuite, mut by_state) in by_ciphersuite {
            let active_keypairs = by_state.remove(&HpkeKeyState::Active).unwrap_or_default();
            let pending_keypairs = by_state.remove(&HpkeKeyState::Pending).unwrap_or_default();
            let expired_keypairs = by_state.remove(&HpkeKeyState::Expired).unwrap_or_default();

            if self.config.ciphersuites.contains(&ciphersuite) {
                let latest_pending_key = pending_keypairs.front();
                let latest_active_key = active_keypairs.front();

                if let Some(latest_pending_key) = latest_pending_key {
                    if duration_since(&self.clock, latest_pending_key.last_state_change_at())
                        > self.config.pending_duration
                    {
                        ops.push(HpkeOp::Update(
                            *latest_pending_key.id(),
                            HpkeKeyState::Active,
                            "ready for promotion",
                        ));

                        if let Some(latest_active_key) = latest_active_key {
                            ops.push(HpkeOp::Update(
                                *latest_active_key.id(),
                                HpkeKeyState::Expired,
                                "pending key ready",
                            ));
                        }
                    }
                } else if latest_pending_key.is_none()
                    && latest_active_key.is_some_and(|keypair| {
                        duration_since(&self.clock, keypair.last_state_change_at())
                            > self.config.active_duration
                    })
                {
                    ops.push(HpkeOp::Create(
                        ciphersuite,
                        HpkeKeyState::Pending,
                        "active key ready for expiration, but no pending key present",
                    ));
                }

                ops.extend(active_keypairs.iter().skip(1).map(|keypair| {
                    HpkeOp::Update(*keypair.id(), HpkeKeyState::Expired, "extraneous key")
                }));
                ops.extend(
                    pending_keypairs
                        .iter()
                        .skip(1)
                        .map(|keypair| HpkeOp::Delete(*keypair.id(), "extraneous key")),
                );
            } else {
                ops.extend(active_keypairs.iter().map(|keypair| {
                    HpkeOp::Update(*keypair.id(), HpkeKeyState::Expired, "unknown ciphersuite")
                }));
                ops.extend(
                    pending_keypairs
                        .iter()
                        .map(|keypair| HpkeOp::Delete(*keypair.id(), "unknown ciphersuite")),
                );
            }

            ops.extend(
                expired_keypairs
                    .iter()
                    .filter(|keypair| {
                        duration_since(&self.clock, keypair.last_state_change_at())
                            > self.config.expired_duration
                    })
                    .map(|keypair| HpkeOp::Delete(*keypair.id(), "expired key")),
            );
        }

        Ok(ops)
    }

    async fn write(
        mut self,
        tx: &Transaction<'_, C>,
        ops: &[HpkeOp],
    ) -> Result<(), DatastoreError> {
        for op in ops {
            match op {
                HpkeOp::Create(ciphersuite, state, reason) => {
                    info!(?ciphersuite, ?state, reason, "creating new key");

                    let id = self.available_ids.next().ok_or_else(|| {
                        DatastoreError::User(anyhow!("global HPKE key ID space exhausted").into())
                    })?;
                    let keypair = generate_hpke_config_and_private_key(
                        id,
                        ciphersuite.kem_id(),
                        ciphersuite.kdf_id(),
                        ciphersuite.aead_id(),
                    )
                    .map_err(|e| DatastoreError::User(e.into()))?;

                    tx.put_global_hpke_keypair(&keypair).await?;
                    tx.set_global_hpke_keypair_state(keypair.config().id(), state)
                        .await?;
                }
                HpkeOp::Update(id, state, reason) => {
                    let keypair = tx.get_global_hpke_keypair(id).await?.ok_or_else(|| {
                        DatastoreError::User(
                            anyhow!("attempted to update state of non-existent key").into(),
                        )
                    })?;
                    info!(?id, old_state = ?keypair.state(), new_state = ?state, reason, "changing key state");
                    tx.set_global_hpke_keypair_state(keypair.id(), state)
                        .await?;
                }
                HpkeOp::Delete(id, reason) => {
                    info!(?id, reason, "deleting key");
                    tx.delete_global_hpke_keypair(id).await?;
                }
            }
        }

        // Defensive assertion: Check our transaction snapshot for at least one active keypair in
        // in the table. If one is absent, committing the transaction would leave Janus unstartable
        // so we should rollback.
        let keypairs = tx.get_global_hpke_keypairs().await?;
        debug!(?keypairs, "table state after running key rotator");
        if !keypairs
            .iter()
            .any(|keypair| keypair.state() == &HpkeKeyState::Active)
        {
            Err(DatastoreError::User(
                anyhow!("unexpected state: no keypairs are active").into(),
            ))
        } else {
            Ok(())
        }
    }
}

enum HpkeOp {
    Create(HpkeCiphersuite, HpkeKeyState, &'static str),
    Update(HpkeConfigId, HpkeKeyState, &'static str),
    Delete(HpkeConfigId, &'static str),
}

/// Enforces that there's at least one [`HpkeCiphersuite`].
pub fn deserialize_hpke_key_rotator_config<'de, D>(
    deserializer: D,
) -> Result<HpkeKeyRotatorConfig, D::Error>
where
    D: Deserializer<'de>,
{
    let config: HpkeKeyRotatorConfig = Deserialize::deserialize(deserializer)?;
    if config.ciphersuites.is_empty() {
        Err(de::Error::custom("must provide at least one ciphersuite"))
    } else {
        Ok(config)
    }
}

/// Returns [`GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL`] times 2, for safety margin.
fn default_pending_duration() -> Duration {
    Duration::from_seconds(GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL.as_secs() * 2)
}

/// 12 weeks. This is long enough not to be unnecessary churn, but short enough that misbehaving
/// clients reveal themselves somewhat imminently.
fn default_active_duration() -> Duration {
    Duration::from_seconds(60 * 60 * 24 * 7 * 12)
}

/// 1 week.
fn default_expired_duration() -> Duration {
    Duration::from_seconds(60 * 60 * 24 * 7)
}

fn default_hpke_ciphersuites() -> HashSet<HpkeCiphersuite> {
    HashSet::from([HpkeCiphersuite::new(
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    )])
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use janus_aggregator_core::datastore::{
        models::{GlobalHpkeKeypair, HpkeKeyState},
        test_util::ephemeral_datastore,
        Datastore,
    };
    use janus_core::{
        hpke::{generate_hpke_config_and_private_key, HpkeCiphersuite},
        test_util::install_test_trace_subscriber,
        time::{Clock, DurationExt, MockClock},
    };
    use janus_messages::{Duration, HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId};

    use crate::aggregator::key_rotator::{HpkeKeyRotatorConfig, KeyRotator};

    async fn get_global_hpke_keypairs<C: Clock>(ds: &Datastore<C>) -> Vec<GlobalHpkeKeypair> {
        ds.run_unnamed_tx(|tx| Box::pin(async move { tx.get_global_hpke_keypairs().await }))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn hpke_key_rotator() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let pending_duration = Duration::from_seconds(60);
        let active_duration = Duration::from_seconds(300);
        let expired_duration = Duration::from_seconds(120);
        let ciphersuite_0 = HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        );
        let ciphersuite_1 = HpkeCiphersuite::new(
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        );
        let ciphersuites = HashSet::from([ciphersuite_0, ciphersuite_1]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // Checks that there's a keypair with the given state for each ciphersuite.
        let ciphersuites = Vec::from([ciphersuite_0, ciphersuite_1]);
        let assert_state = |keypairs: &[GlobalHpkeKeypair], state: HpkeKeyState| {
            assert!(ciphersuites.iter().all(|ciphersuite| {
                keypairs.iter().any(|keypair| {
                    keypair.state() == &state && &keypair.ciphersuite() == ciphersuite
                })
            }));
        };

        // First iteration: We should create active keys for each ciphersuite.
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 2);
        assert_state(&keypairs, HpkeKeyState::Active);

        // Advance the clock only a little, no action should be taken.
        clock.advance(&Duration::from_seconds(1));
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 2);
        assert_state(&keypairs, HpkeKeyState::Active);

        // Run through several lifetimes.
        for _ in 0..4 {
            // Age out the keys. We should insert a couple of pending keys.
            clock.advance(&active_duration.add(&Duration::from_seconds(1)).unwrap());
            key_rotator.run().await.unwrap();
            let keypairs = get_global_hpke_keypairs(&ds).await;
            assert_eq!(keypairs.len(), 4);
            assert_state(&keypairs, HpkeKeyState::Active);
            assert_state(&keypairs, HpkeKeyState::Pending);

            // Advance the clock only a little, no action should be taken.
            clock.advance(&Duration::from_seconds(1));
            key_rotator.run().await.unwrap();
            let keypairs = get_global_hpke_keypairs(&ds).await;
            assert_eq!(keypairs.len(), 4);
            assert_state(&keypairs, HpkeKeyState::Active);
            assert_state(&keypairs, HpkeKeyState::Pending);

            // Move past the pending duration, we should promote the new keypairs to active and the
            // old ones to expired.
            clock.advance(&pending_duration.add(&Duration::from_seconds(1)).unwrap());
            key_rotator.run().await.unwrap();
            let keypairs = get_global_hpke_keypairs(&ds).await;
            assert_eq!(keypairs.len(), 4);
            assert_state(&keypairs, HpkeKeyState::Active);
            assert_state(&keypairs, HpkeKeyState::Expired);

            // Advance the clock only a little, no action should be taken.
            clock.advance(&Duration::from_seconds(1));
            key_rotator.run().await.unwrap();
            let keypairs = get_global_hpke_keypairs(&ds).await;
            assert_eq!(keypairs.len(), 4);
            assert_state(&keypairs, HpkeKeyState::Active);
            assert_state(&keypairs, HpkeKeyState::Expired);

            // Move past the expiration duration, we should remove the old keys.
            clock.advance(&expired_duration.add(&Duration::from_seconds(1)).unwrap());
            key_rotator.run().await.unwrap();
            let keypairs = get_global_hpke_keypairs(&ds).await;
            assert_eq!(keypairs.len(), 2);
            assert_state(&keypairs, HpkeKeyState::Active);
        }
    }

    #[tokio::test]
    async fn hpke_key_rotator_new_config() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let pending_duration = Duration::from_seconds(60);
        let active_duration = Duration::from_seconds(300);
        let expired_duration = Duration::from_seconds(60);
        let ciphersuite_0 = HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        );
        let ciphersuites = HashSet::from([ciphersuite_0]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // Run the key rotator for a while.
        for _ in 0..18 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }

        // Add a new ciphersuite to the config.
        let ciphersuite_1 = HpkeCiphersuite::new(
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        );
        let ciphersuites = HashSet::from([ciphersuite_0, ciphersuite_1]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // Run the key rotator, we should insert a new pending key for the new ciphersuite.
        clock.advance(&Duration::from_seconds(1));
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.ciphersuite() == ciphersuite_1)
            .collect();
        assert_eq!(keypairs.len(), 1);
        assert_eq!(keypairs[0].state(), &HpkeKeyState::Pending);

        // Nothing should change.
        clock.advance(&Duration::from_seconds(1));
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.ciphersuite() == ciphersuite_1)
            .collect();
        assert_eq!(keypairs.len(), 1);
        assert_eq!(keypairs[0].state(), &HpkeKeyState::Pending);

        // Move past the pending duration, we should promote the new keypair.
        clock.advance(&pending_duration.add(&Duration::from_seconds(1)).unwrap());
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.ciphersuite() == ciphersuite_1)
            .collect();
        assert_eq!(keypairs.len(), 1);
        assert_eq!(keypairs[0].state(), &HpkeKeyState::Active);
    }

    #[tokio::test]
    async fn hpke_key_rotator_multiple_pending_keys() {
        // Should only promote the latest pending key.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let pending_duration = Duration::from_seconds(60);
        let active_duration = Duration::from_seconds(300);
        let expired_duration = Duration::from_seconds(60);
        let ciphersuite_0 = HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        );
        let ciphersuites = HashSet::from([ciphersuite_0]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // Run the key rotator for a while, such that the current key is expired with one pending.
        for _ in 0..12 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 2);

        // Advance long enough to make the pending key ready. We should still prioritize the promoting
        // the newest inserted key.
        clock.advance(&Duration::from_seconds(300));

        // Operator inserts a new key in the pending state.
        let id = HpkeConfigId::from(255);
        ds.run_unnamed_tx(|tx| {
            Box::pin(async move {
                tx.put_global_hpke_keypair(
                    &generate_hpke_config_and_private_key(
                        id,
                        ciphersuite_0.kem_id(),
                        ciphersuite_0.kdf_id(),
                        ciphersuite_0.aead_id(),
                    )
                    .unwrap(),
                )
                .await
            })
        })
        .await
        .unwrap();

        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 2);
        assert!(keypairs
            .iter()
            .any(|keypair| keypair.state() == &HpkeKeyState::Active));
        let pending_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Pending)
            .collect();
        assert_eq!(pending_keypairs.len(), 1);
        assert!(pending_keypairs[0].id() == &id);

        // Move past the pending duration, we should promote the latest inserted pending keypair.
        clock.advance(&pending_duration.add(&Duration::from_seconds(1)).unwrap());
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let active_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Active)
            .collect();
        assert_eq!(active_keypairs.len(), 1);
        assert!(active_keypairs[0].id() == &id);
    }

    #[tokio::test]
    async fn hpke_key_rotator_multiple_active_keys() {
        // If the operator inserts multiple active keys, we should replace them with only one key.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let pending_duration = Duration::from_seconds(60);
        let active_duration = Duration::from_seconds(300);
        let expired_duration = Duration::from_seconds(60);
        let ciphersuite_0 = HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        );

        let ciphersuites = HashSet::from([ciphersuite_0]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // Run the key rotator for a while.
        for _ in 0..18 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }

        // Operator inserts a new key in the active state.
        let id = HpkeConfigId::from(255);
        ds.run_unnamed_tx(|tx| {
            Box::pin(async move {
                tx.put_global_hpke_keypair(
                    &generate_hpke_config_and_private_key(
                        id,
                        ciphersuite_0.kem_id(),
                        ciphersuite_0.kdf_id(),
                        ciphersuite_0.aead_id(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
                tx.set_global_hpke_keypair_state(&id, &HpkeKeyState::Active)
                    .await
                    .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();

        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let active_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Active)
            .collect();
        assert_eq!(active_keypairs.len(), 1);
        // `id` should be the active key, since it was inserted more recently.
        assert_eq!(active_keypairs[0].id(), &id);
    }

    #[tokio::test]
    async fn hpke_key_rotator_refuse_to_remove_only_key() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let pending_duration = Duration::from_seconds(60);
        let active_duration = Duration::from_seconds(300);
        let expired_duration = Duration::from_seconds(60);
        let ciphersuite_0 = HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        );

        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: HashSet::new(),
            },
        );

        assert!(key_rotator.run().await.is_err());

        let ciphersuites = HashSet::from([ciphersuite_0]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        for _ in 0..7 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }

        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: HashSet::new(),
            },
        );

        assert!(key_rotator.run().await.is_err());
    }

    #[tokio::test]
    async fn hpke_key_rotator_remove_config() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let ds = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let pending_duration = Duration::from_seconds(60);
        let active_duration = Duration::from_seconds(300);
        let expired_duration = Duration::from_seconds(120);
        let ciphersuite_0 = HpkeCiphersuite::new(
            HpkeKemId::P256HkdfSha256,
            HpkeKdfId::HkdfSha256,
            HpkeAeadId::Aes128Gcm,
        );
        let ciphersuite_1 = HpkeCiphersuite::new(
            HpkeKemId::X25519HkdfSha256,
            HpkeKdfId::HkdfSha512,
            HpkeAeadId::Aes256Gcm,
        );
        let ciphersuites = HashSet::from([ciphersuite_0, ciphersuite_1]);

        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // Run the key rotator for a while, such that the current key is expired with one pending.
        for _ in 0..12 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 4);

        // Remove ciphersuite_0 from the config.
        let ciphersuites = HashSet::from([ciphersuite_1]);
        let key_rotator = KeyRotator::new(
            ds.clone(),
            HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuites: ciphersuites.clone(),
            },
        );

        // The pending key should be gone, and the active key should be expired.
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let ciphersuite_0_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.ciphersuite() == ciphersuite_0)
            .collect();
        assert_eq!(ciphersuite_0_keypairs.len(), 1);
        assert!(ciphersuite_0_keypairs[0].state() == &HpkeKeyState::Expired);

        clock.advance(&expired_duration.add(&Duration::from_seconds(1)).unwrap());
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let ciphersuite_0_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.ciphersuite() == ciphersuite_0)
            .collect();
        assert!(ciphersuite_0_keypairs.is_empty());
    }
}
