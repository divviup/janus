use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

#[allow(unused_imports)]
use crate::aggregator::Config as AggregatorConfig; // used in doccomment.
use crate::cache::GlobalHpkeKeypairCache;
use anyhow::{anyhow, Error};
use derivative::Derivative;
use futures::{future::try_join_all, FutureExt};
use janus_aggregator_core::datastore::{
    models::{GlobalHpkeKeypair, HpkeKeyState},
    Datastore, Error as DatastoreError, Transaction,
};
use janus_core::{
    hpke::{HpkeCiphersuite, HpkeKeypair},
    time::{Clock, TimeExt},
};
use janus_messages::{Duration, HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId, Time};
use serde::{de, Deserialize, Deserializer, Serialize};
use tokio::try_join;
use tracing::{debug, info};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

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
#[serde(deny_unknown_fields)]
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

impl Default for HpkeKeyRotatorConfig {
    fn default() -> Self {
        Self {
            pending_duration: default_pending_duration(),
            active_duration: default_active_duration(),
            expired_duration: default_expired_duration(),
            ciphersuites: default_hpke_ciphersuites(),
        }
    }
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

        let keypairs = tx
            .get_global_hpke_keypairs()
            .inspect(|keypairs| debug!(?keypairs, "table state before running key rotator"))
            .await?
            .into_iter()
            .map(|keypair| (*keypair.id(), keypair))
            .collect();

        HpkeKeyRotator::new(tx.clock().clone(), keypairs, config)?
            .sweep()?
            .write(tx)
            .await
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
    fn new(
        clock: C,
        keypairs: HashMap<HpkeConfigId, GlobalHpkeKeypair>,
        config: &'a HpkeKeyRotatorConfig,
    ) -> Result<Self, DatastoreError> {
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
            clock,
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
    fn sweep(mut self) -> Result<Self, DatastoreError> {
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
        for keypair in self.keypairs.values() {
            let by_state = by_ciphersuite.entry(keypair.ciphersuite()).or_default();
            let keypairs = by_state.entry(*keypair.state()).or_default();
            keypairs.insert(
                keypairs.partition_point(|&candidate| {
                    candidate.last_state_change_at() > keypair.last_state_change_at()
                }),
                keypair,
            );
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
                } else if latest_active_key.is_some_and(|keypair| {
                    duration_since(&self.clock, keypair.last_state_change_at())
                        > self.config.active_duration
                }) {
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

        // Write ops in a separate loop, to avoid iterator invalidation problems.
        for op in ops {
            match op {
                HpkeOp::Create(ciphersuite, state, reason) => {
                    info!(?ciphersuite, ?state, reason, "creating new key");

                    let id = self.available_ids.next().ok_or_else(|| {
                        DatastoreError::User(anyhow!("global HPKE key ID space exhausted").into())
                    })?;
                    let keypair = HpkeKeypair::generate(
                        id,
                        ciphersuite.kem_id(),
                        ciphersuite.kdf_id(),
                        ciphersuite.aead_id(),
                    )
                    .map_err(|e| DatastoreError::User(e.into()))?;

                    let result = self
                        .keypairs
                        .insert(id, GlobalHpkeKeypair::new(keypair, state, self.clock.now()));
                    // It is a programmer error to attempt to insert a key where one already exists.
                    assert!(result.is_none());
                }
                HpkeOp::Update(id, state, reason) => {
                    // Unwrap safety: it is a bug to attempt to mutate a non-existent key.
                    let keypair = self.keypairs.get_mut(&id).unwrap();
                    info!(?id, old_state = ?keypair.state(), new_state = ?state, reason, "changing key state");
                    keypair.set_state(state, self.clock.now());
                }
                HpkeOp::Delete(id, reason) => {
                    // Unwrap safety: it is a bug to delete a non-existent key.
                    info!(?id, reason, "deleting key");
                    self.keypairs.remove(&id).unwrap();
                }
            }
        }

        Ok(self)
    }

    async fn write(&self, tx: &Transaction<'_, C>) -> Result<(), DatastoreError> {
        let current_keypairs_ids: HashSet<_> = tx
            .get_global_hpke_keypairs()
            .await?
            .into_iter()
            .map(|keypair| *keypair.id())
            .collect();
        let update_keypairs_ids: HashSet<_> = self.keypairs.keys().cloned().collect();
        let to_delete: Vec<_> = current_keypairs_ids
            .difference(&update_keypairs_ids)
            .collect();

        try_join!(
            try_join_all(
                to_delete
                    .iter()
                    .map(|id| async move { tx.delete_global_hpke_keypair(id).await })
            ),
            try_join_all(
                self.keypairs
                    .iter()
                    .map(|(id, updated_keypair)| async move {
                        match tx.get_global_hpke_keypair(id).await? {
                            Some(current_keypair) => {
                                if current_keypair.state() != updated_keypair.state() {
                                    tx.set_global_hpke_keypair_state(
                                        updated_keypair.id(),
                                        updated_keypair.state(),
                                    )
                                    .await?;
                                }
                                Ok(())
                            }
                            None => {
                                tx.put_global_hpke_keypair(updated_keypair.hpke_keypair())
                                    .await?;
                                tx.set_global_hpke_keypair_state(
                                    updated_keypair.id(),
                                    updated_keypair.state(),
                                )
                                .await?;
                                Ok(())
                            }
                        }
                    })
            ),
        )?;

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
pub fn default_pending_duration() -> Duration {
    Duration::from_seconds(GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL.as_secs() * 2)
}

/// 12 weeks. This is long enough not to be unnecessary churn, but short enough that misbehaving
/// clients reveal themselves somewhat imminently.
pub fn default_active_duration() -> Duration {
    Duration::from_seconds(60 * 60 * 24 * 7 * 12)
}

/// 1 week.
pub fn default_expired_duration() -> Duration {
    Duration::from_seconds(60 * 60 * 24 * 7)
}

pub fn default_hpke_ciphersuites() -> HashSet<HpkeCiphersuite> {
    HashSet::from([HpkeCiphersuite::new(
        HpkeKemId::X25519HkdfSha256,
        HpkeKdfId::HkdfSha256,
        HpkeAeadId::Aes128Gcm,
    )])
}

#[cfg(test)]
impl Arbitrary for HpkeKeyRotatorConfig {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut ciphersuites = HashSet::arbitrary(&mut Gen::new(4));
        // Ensure we have at least one ciphersuite in the config.
        ciphersuites.insert(HpkeCiphersuite::arbitrary(g));

        Self {
            // Use u32 cast to u64 to avoid overflowing time.
            pending_duration: Duration::from_seconds(u32::arbitrary(g).into()),
            active_duration: Duration::from_seconds(u32::arbitrary(g).into()),
            expired_duration: Duration::from_seconds(u32::arbitrary(g).into()),
            ciphersuites,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use itertools::Itertools;
    use janus_aggregator_core::datastore::{
        models::{GlobalHpkeKeypair, HpkeKeyState},
        test_util::ephemeral_datastore,
        Datastore,
    };
    use janus_core::{
        hpke::{HpkeCiphersuite, HpkeKeypair},
        test_util::install_test_trace_subscriber,
        time::{Clock, DurationExt, MockClock},
    };
    use janus_messages::{Duration, HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId, Time};
    use quickcheck::{Arbitrary, Gen, TestResult};
    use quickcheck_macros::quickcheck;

    use crate::aggregator::key_rotator::{duration_since, HpkeKeyRotatorConfig, KeyRotator};

    use super::HpkeKeyRotator;

    async fn get_global_hpke_keypairs<C: Clock>(ds: &Datastore<C>) -> Vec<GlobalHpkeKeypair> {
        ds.run_unnamed_tx(|tx| Box::pin(async move { tx.get_global_hpke_keypairs().await }))
            .await
            .unwrap()
    }

    // Exercises the happy path and database interaction of the key rotator.
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

    #[derive(Debug, Clone)]
    struct InitialGlobalHpkeKeysState {
        /// Where the clock should start.
        start: Time,
        keypairs: HashMap<HpkeConfigId, GlobalHpkeKeypair>,
    }

    impl Arbitrary for InitialGlobalHpkeKeysState {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let start = u32::arbitrary(g) as u64;

            // Allow some timestamps to be in the future, within reason.
            let offset = start + u8::arbitrary(g) as u64;

            // Use at most 32 distinct keypairs.
            let ids: HashSet<u8> = HashSet::arbitrary(&mut Gen::new(32));

            let keypairs = ids
                .into_iter()
                .map(|id| {
                    (
                        HpkeConfigId::from(id),
                        GlobalHpkeKeypair::new(
                            HpkeKeypair::test_with_ciphersuite(id, HpkeCiphersuite::arbitrary(g)),
                            *g.choose(&[
                                HpkeKeyState::Pending,
                                HpkeKeyState::Active,
                                HpkeKeyState::Expired,
                            ])
                            .unwrap(),
                            Time::from_seconds_since_epoch(
                                (start + offset).saturating_sub(u32::arbitrary(g) as u64),
                            ),
                        ),
                    )
                })
                .collect();
            Self {
                start: Time::from_seconds_since_epoch(start),
                keypairs,
            }
        }
    }

    // For each known ciphersuite, if there was an active key before running the key rotator, we
    // must retain an active key.
    #[quickcheck]
    fn hpke_key_rotator_at_least_one_active_key_per_active_ciphersuite(
        config: HpkeKeyRotatorConfig,
        state: InitialGlobalHpkeKeysState,
    ) -> TestResult {
        let clock = MockClock::new(state.start);

        let known_ciphersuites_with_active_keys: Vec<_> = config
            .ciphersuites
            .iter()
            .filter(|&ciphersuite| {
                state.keypairs.iter().any(|(_, keypair)| {
                    keypair.state() == &HpkeKeyState::Active
                        && ciphersuite == &keypair.ciphersuite()
                })
            })
            .collect();

        let key_rotator = HpkeKeyRotator::new(clock, state.keypairs, &config)
            .unwrap()
            .sweep()
            .unwrap();

        for known_ciphersuite in known_ciphersuites_with_active_keys {
            if !key_rotator.keypairs.iter().any(|(_, keypair)| {
                &keypair.ciphersuite() == known_ciphersuite
                    && keypair.state() == &HpkeKeyState::Active
            }) {
                return TestResult::failed();
            }
        }
        TestResult::passed()
    }

    #[quickcheck]
    fn hpke_key_rotator_remove_config(
        config: HpkeKeyRotatorConfig,
        state: InitialGlobalHpkeKeysState,
    ) -> TestResult {
        let clock = MockClock::new(state.start);

        let to_expire: HashSet<_> = state
            .keypairs
            .iter()
            .filter(|(_, keypair)| {
                !config.ciphersuites.contains(&keypair.ciphersuite())
                    && keypair.state() == &HpkeKeyState::Active
            })
            .map(|(id, _)| *id)
            .collect();

        let to_delete: HashSet<_> = state
            .keypairs
            .iter()
            .filter(|(_, keypair)| {
                !config.ciphersuites.contains(&keypair.ciphersuite())
                    && keypair.state() == &HpkeKeyState::Pending
            })
            .map(|(id, _)| *id)
            .collect();

        if to_expire.is_empty() && to_delete.is_empty() {
            return TestResult::discard();
        }

        let key_rotator = HpkeKeyRotator::new(clock, state.keypairs, &config)
            .unwrap()
            .sweep()
            .unwrap();

        if to_delete
            .iter()
            .any(|id| key_rotator.keypairs.contains_key(id))
        {
            TestResult::error("pending key should have been deleted")
        } else if !to_expire
            .iter()
            .all(|id| key_rotator.keypairs.get(id).unwrap().state() == &HpkeKeyState::Expired)
        {
            TestResult::error("active key should have been expired")
        } else {
            TestResult::passed()
        }
    }

    #[quickcheck]
    fn hpke_key_rotator_new_config(
        config: HpkeKeyRotatorConfig,
        state: InitialGlobalHpkeKeysState,
    ) -> TestResult {
        if state.keypairs.is_empty() {
            return TestResult::discard();
        }
        let clock = MockClock::new(state.start);

        let ciphersuites_to_insert: Vec<_> = config
            .ciphersuites
            .iter()
            .filter(|&ciphersuite| {
                !state
                    .keypairs
                    .iter()
                    .any(|(_, keypair)| &keypair.ciphersuite() == ciphersuite)
            })
            .collect();

        let key_rotator = HpkeKeyRotator::new(clock, state.keypairs, &config)
            .unwrap()
            .sweep()
            .unwrap();

        for ciphersuite in ciphersuites_to_insert {
            let inserted: Vec<_> = key_rotator
                .keypairs
                .iter()
                .filter(|(_, keypair)| &keypair.ciphersuite() == ciphersuite)
                .collect();
            if inserted.len() != 1 {
                return TestResult::error("more than one key inserted for new ciphersuite");
            } else if inserted[0].1.state() != &HpkeKeyState::Pending {
                return TestResult::error("inserted key not in pending state");
            }
        }
        TestResult::passed()
    }

    #[quickcheck]
    fn hpke_key_rotator_active_keys(
        config: HpkeKeyRotatorConfig,
        state: InitialGlobalHpkeKeysState,
    ) -> TestResult {
        let clock = MockClock::new(state.start);
        let key_rotator = HpkeKeyRotator::new(clock.clone(), state.keypairs, &config)
            .unwrap()
            .sweep()
            .unwrap();

        for ciphersuite in &config.ciphersuites {
            let active_keys: Vec<_> = key_rotator
                .keypairs
                .values()
                .filter(|&keypair| {
                    keypair.ciphersuite() == *ciphersuite
                        && keypair.state() == &HpkeKeyState::Active
                })
                .collect();

            if active_keys.len() > 1 {
                return TestResult::error("there should be at most 1 active key");
            } else if active_keys.len() == 1
                && duration_since(&clock, active_keys[0].last_state_change_at())
                    > config.active_duration
                && !key_rotator.keypairs.values().any(|keypair| {
                    keypair.state() == &HpkeKeyState::Pending
                        && &keypair.ciphersuite() == ciphersuite
                })
            {
                return TestResult::error("no pending key present for expiring key");
            }
        }

        TestResult::passed()
    }

    #[quickcheck]
    fn hpke_key_rotator_pending_keys(
        config: HpkeKeyRotatorConfig,
        state: InitialGlobalHpkeKeysState,
    ) -> TestResult {
        let clock = MockClock::new(state.start);
        let key_rotator = HpkeKeyRotator::new(clock, state.keypairs.clone(), &config)
            .unwrap()
            .sweep()
            .unwrap();

        for ciphersuite in &config.ciphersuites {
            let newest_pending_keys_ids: HashSet<_> = state
                .keypairs
                .values()
                .filter(|&keypair| {
                    &keypair.ciphersuite() == ciphersuite
                        && keypair.state() == &HpkeKeyState::Pending
                })
                .max_set_by_key(|keypair| keypair.last_state_change_at())
                .into_iter()
                .map(|keypair| *keypair.id())
                .collect();

            let pending_keys: Vec<_> = key_rotator
                .keypairs
                .values()
                .filter(|&keypair| {
                    &keypair.ciphersuite() == ciphersuite
                        && keypair.state() == &HpkeKeyState::Pending
                })
                .collect();

            if pending_keys.len() > 1 {
                return TestResult::error("there should be at most 1 pending key");
            } else if pending_keys.len() == 1
                && !newest_pending_keys_ids.is_empty()
                && !newest_pending_keys_ids.contains(pending_keys[0].id())
            {
                return TestResult::error("only the newest pending key should remain");
            }
        }

        TestResult::passed()
    }

    #[quickcheck]
    fn hpke_key_rotator_expired_keys(
        config: HpkeKeyRotatorConfig,
        state: InitialGlobalHpkeKeysState,
    ) -> TestResult {
        let clock = MockClock::new(state.start);

        let to_delete: HashSet<_> = state
            .keypairs
            .iter()
            .filter(|(_, keypair)| {
                duration_since(&clock, keypair.last_state_change_at()) > config.expired_duration
                    && keypair.state() == &HpkeKeyState::Expired
            })
            .map(|(id, _)| *id)
            .collect();

        if to_delete.is_empty() {
            return TestResult::discard();
        }

        let key_rotator = HpkeKeyRotator::new(clock, state.keypairs, &config)
            .unwrap()
            .sweep()
            .unwrap();

        for id in to_delete {
            if key_rotator.keypairs.contains_key(&id) {
                return TestResult::error("expired key was not deleted");
            }
        }

        TestResult::passed()
    }
}
