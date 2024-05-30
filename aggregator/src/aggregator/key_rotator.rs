use std::sync::Arc;

#[allow(unused_imports)]
use crate::aggregator::Config as AggregatorConfig; // used in doccomment.
use anyhow::{anyhow, Error};
use janus_aggregator_core::datastore::{
    models::{GlobalHpkeKeypair, HpkeKeyState},
    Datastore, Error as DatastoreError, Transaction,
};
use janus_core::{
    hpke::{generate_hpke_config_and_private_key, HpkeCiphersuite},
    time::{Clock, TimeExt},
};
use janus_messages::{Duration, HpkeConfigId, Time};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Handles key rotation for Janus, according to policies defined in the configuration.
///
/// # Global HPKE Keys
///
/// The key rotator can handle key rotation for global HPKE keys. The key rotator is tolerant of
/// some manual operator changes to the `global_hpke_keys` table.
///
/// Operators _must not_ manually change the `created_at` or `updated_at` columns, as these are
/// used for rotation decision-making.
///
/// It is strongly discouraged to:
///   - Delete active or expired keypairs too early, as that would leave Janus unable to decrypt
///     report shares using the keypair.
///   - Promote pending keypairs too early, unless all Janus replicas have been rebooted since
///     their insertion.
///   - Directly insert active keypairs.
/// Keypairs that are manually inserted are adopted by the key rotator and will have their lifecycle
/// managed. The number of keypairs per ciphersuite will trend towards 1, i.e. 2 keys with the same
/// ciphersuite will eventually be replaced with 1 key.
#[derive(Debug)]
pub struct KeyRotator<C: Clock> {
    datastore: Arc<Datastore<C>>,
    hpke: Vec<HpkeKeyRotatorConfig>,
}

/// Defines the ciphersuite and rotation policy of a global HPKE key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeKeyRotatorConfig {
    /// How long key remains in [`HpkeKeyState::Pending`] before being moved to
    /// [`HpkeKeyState::Active`]. This should be greater than
    /// [`AggregatorConfig::global_hpke_configs_refresh_interval`].
    pub pending_duration: Duration,

    /// The time-to-live of the key. Once this is exceeded, the key is moved to
    /// [`HpkeKeyState::Expired`]. It is at operator discretion as to how long this should be.
    pub active_duration: Duration,

    /// How long the key remains in [`HpkeKeyState::Expired`] before being deleted. This should
    /// be greater than the clients' HPKE key cache maximum age.
    pub expired_duration: Duration,

    /// The ciphersuite of the key.
    pub ciphersuite: HpkeCiphersuite,

    /// Safely phase out this ciphersuite. This will immediately delete any pending keys and
    /// expire any active keys. Expired keys are retained for at least [`Self::expired_duration`]
    /// before being deleted.
    ///
    /// After [`Self::expired_duration`], this config can be removed entirely. It is not recommended
    /// to remove key configurations without running the key rotator with `retire` first.
    ///
    /// There must be at least one non-retired config present with its key in the active state. If
    /// this is the only config and it is marked retired, the key rotator will refuse to run.
    pub retire: bool,
}

impl<C: Clock> KeyRotator<C> {
    pub fn new(datastore: Arc<Datastore<C>>, hpke: Vec<HpkeKeyRotatorConfig>) -> Self {
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
    #[tracing::instrument]
    pub async fn run(&self) -> Result<(), Error> {
        self.datastore
            .run_tx("global_hpke_key_rotator", |tx| {
                let configs = self.hpke.clone();
                Box::pin(async move { Self::run_hpke(tx, configs).await })
            })
            .await
            .map_err(|err| err.into())
    }

    #[tracing::instrument(skip(tx))]
    async fn run_hpke(
        tx: &Transaction<'_, C>,
        configs: Vec<HpkeKeyRotatorConfig>,
    ) -> Result<(), DatastoreError> {
        // Take an ExclusiveLock on the table. This ensures that only one key rotator
        // replica writes to the table at a time and that each replica gets a consistent
        // view of the table state.
        //
        // ExclusiveLock does not conflict with the AccessShare lock taken by table
        // reads, i.e. other aggregator replicas can continue to refresh their key
        // caches without being blocked.
        tx.lock_global_hpke_keypairs().await?;

        let current_keypairs = tx.get_global_hpke_keypairs().await?;
        debug!(?current_keypairs, "before");
        let mut available_ids = Self::available_ids(&current_keypairs);
        for config in &configs {
            Self::run_hpke_for_config(tx, &current_keypairs, &mut available_ids, config).await?;
        }

        // Defensive assertion: Check our transaction snapshot for at least one active keypair in
        // in the table. If one is absent, committing the transaction would leave Janus unstartable
        // so we should rollback. This captures any bugs, and if the operator is trying to retire
        // the last available key.
        let current_keypairs = tx.get_global_hpke_keypairs().await?;
        debug!(?current_keypairs, "after");
        if !current_keypairs
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

    #[tracing::instrument(skip(tx, current_keypairs, available_ids))]
    async fn run_hpke_for_config(
        tx: &Transaction<'_, C>,
        current_keypairs: &[GlobalHpkeKeypair],
        available_ids: &mut impl Iterator<Item = HpkeConfigId>,
        config: &HpkeKeyRotatorConfig,
    ) -> Result<(), DatastoreError> {
        let clock = tx.clock();

        let PartitionedKeypairs {
            pending: pending_keypairs,
            active: active_keypairs,
            expired: expired_keypairs,
        } = Self::partition_keypairs(current_keypairs, &config.ciphersuite);

        let mut next_key = || {
            generate_hpke_config_and_private_key(
                available_ids
                    .next()
                    .ok_or_else(|| DatastoreError::User(anyhow!("u8 space exhausted").into()))?,
                config.ciphersuite.kem_id(),
                config.ciphersuite.kdf_id(),
                config.ciphersuite.aead_id(),
            )
            .map_err(|e| DatastoreError::User(e.into()))
        };

        if config.retire {
            for keypair in pending_keypairs {
                // Janus replicas should have never advertised this keypair, so it should be safe
                // to delete outright.
                info!(id = ?keypair.id(), "deleting pending keypair for retired ciphersuite");
                tx.delete_global_hpke_keypair(keypair.id()).await?;
            }
            for keypair in active_keypairs {
                info!(id = ?keypair.id(), "expiring active keypair for retired ciphersuite");
                tx.set_global_hpke_keypair_state(keypair.id(), &HpkeKeyState::Expired)
                    .await?;
            }
        } else if active_keypairs.is_empty() && pending_keypairs.is_empty() {
            // Bootstrapping case: there are no keys at all for this ciphersuite, so we need to
            // insert one.
            let keypair = next_key()?;
            info!(
                id = ?keypair.config().id(),
                "bootstrapping: inserting key for new ciphersuite"
            );
            tx.put_global_hpke_keypair(&keypair).await?;

            // If there are zero keypairs reported by the database, it's likely beacuse we're
            // in a brand new database, and this is the first execution of Janus. Initialize
            // the table with active keys. Janus won't be ready until there's at least one
            // active keypair in the database.
            //
            // Otherwise, the ciphersuite was likely added to the configuration and its key
            // needs to go through the normal pending->active state change.
            if current_keypairs.is_empty() {
                info!(id = ?keypair.config().id(), "bootstrapping: moving new key to active state");
                tx.set_global_hpke_keypair_state(keypair.config().id(), &HpkeKeyState::Active)
                    .await?;
            }
        } else {
            let to_be_expired_keypairs: Vec<_> = active_keypairs
                .iter()
                .filter(|keypair| {
                    Self::duration_since(clock, keypair.updated_at()) > config.active_duration
                })
                .cloned()
                .collect();

            if to_be_expired_keypairs != active_keypairs {
                for keypair in to_be_expired_keypairs {
                    info!(id = ?keypair.id(), "multiple active keys are present, marking key expired");
                    tx.set_global_hpke_keypair_state(keypair.id(), &HpkeKeyState::Expired)
                        .await?;
                }
            } else {
                if pending_keypairs.is_empty() {
                    let next = next_key()?;
                    info!(id = ?next.config().id(), "inserting new pending key to replace expired one(s)");
                    tx.put_global_hpke_keypair(&next).await?;
                } else {
                    let pending_key_is_ready = pending_keypairs.iter().any(|keypair| {
                        Self::duration_since(clock, keypair.updated_at()) > config.pending_duration
                    });
                    if pending_key_is_ready {
                        for keypair in to_be_expired_keypairs {
                            info!(id = ?keypair.id(), "a pending key is ready, marking key expired");
                            tx.set_global_hpke_keypair_state(keypair.id(), &HpkeKeyState::Expired)
                                .await?;
                        }
                    }
                }
            }

            // Promote any pending keypairs that are ready. We don't sweep them in the same loop
            // as active keypairs, because it's possible for there to be a pending keypair
            // without an active one.
            for pending_keypair in pending_keypairs {
                if Self::duration_since(clock, pending_keypair.updated_at())
                    > config.pending_duration
                {
                    info!(id = ?pending_keypair.id(), "pending key is ready, moving it to active");
                    tx.set_global_hpke_keypair_state(pending_keypair.id(), &HpkeKeyState::Active)
                        .await?;
                }
            }
        }

        for keypair in &expired_keypairs {
            if Self::duration_since(clock, keypair.updated_at()) > config.expired_duration {
                info!(id = ?keypair.id(), "deleting expired keypair");
                tx.delete_global_hpke_keypair(keypair.id()).await?;
            }
        }

        Ok(())
    }

    fn duration_since(clock: &C, time: &Time) -> Duration {
        // Use saturating difference to account for time skew between key rotator runners. Since
        // key rotators are synchronized by an exclusive lock on the table, it's possible that
        // time skew between concurrently running replicas result in underflows.
        clock.now().saturating_difference(time)
    }

    fn partition_keypairs<'a>(
        keypairs: &'a [GlobalHpkeKeypair],
        ciphersuite: &HpkeCiphersuite,
    ) -> PartitionedKeypairs<'a> {
        let mut ret = PartitionedKeypairs::default();
        keypairs
            .iter()
            .filter(|keypair| &keypair.ciphersuite() == ciphersuite)
            .for_each(|keypair| match keypair.state() {
                HpkeKeyState::Pending => ret.pending.push(keypair),
                HpkeKeyState::Active => ret.active.push(keypair),
                HpkeKeyState::Expired => ret.expired.push(keypair),
            });
        ret
    }

    fn available_ids(current_keypairs: &[GlobalHpkeKeypair]) -> impl Iterator<Item = HpkeConfigId> {
        let ids: Vec<_> = current_keypairs
            .iter()
            .map(|keypair| u8::from(*keypair.id()))
            .collect();

        // Try to cycle through the entire u8 space before going back to zero. This allows us a
        // bigger window to quicky reject reports from faulty old clients with an outdated HPKE
        // config error, rather than attempting to decrypt them with the wrong key.
        let newest_id = current_keypairs
            .iter()
            .max_by(|a, b| a.created_at().cmp(b.created_at()))
            .map(|keypair| (*keypair.id()).into())
            .unwrap_or(0);
        (newest_id..=u8::MAX)
            .chain(0..newest_id)
            .filter_map(move |id| {
                if !ids.contains(&id) {
                    Some(HpkeConfigId::from(id))
                } else {
                    None
                }
            })
    }
}

#[derive(Default)]
struct PartitionedKeypairs<'a> {
    pending: Vec<&'a GlobalHpkeKeypair>,
    active: Vec<&'a GlobalHpkeKeypair>,
    expired: Vec<&'a GlobalHpkeKeypair>,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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

        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_0.clone(),
                    retire: false,
                },
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_1.clone(),
                    retire: false,
                },
            ]),
        );

        // Checks that there's a keypair with the given state for each ciphersuite.
        let ciphersuites = Vec::from([ciphersuite_0, ciphersuite_1]);
        let assert_state = |keypairs: &[GlobalHpkeKeypair], state: HpkeKeyState| {
            assert!(ciphersuites.iter().all(|ciphersuite| keypairs
                .iter()
                .find(|keypair| keypair.state() == &state && &keypair.ciphersuite() == ciphersuite)
                .is_some()));
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

        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuite: ciphersuite_0.clone(),
                retire: false,
            }]),
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
        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_0.clone(),
                    retire: false,
                },
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_1.clone(),
                    retire: false,
                },
            ]),
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
        // While the key rotator only inserts pending keys one a at a time, it should respect if the
        // operator has inserted a pending key themselves while one is in flight.
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
            Vec::from([HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuite: ciphersuite_0.clone(),
                retire: false,
            }]),
        );

        // Run the key rotator for a while, such that the current key is expired with one pending.
        for _ in 0..12 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 2);

        // Operator inserts a new key in the pending state.
        let id = HpkeConfigId::from(255);
        ds.run_unnamed_tx(|tx| {
            let ciphersuite_0 = ciphersuite_0.clone();
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
        assert_eq!(keypairs.len(), 3);
        assert!(keypairs
            .iter()
            .find(|keypair| keypair.state() == &HpkeKeyState::Active)
            .is_some());
        let pending_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Pending)
            .collect();
        assert_eq!(pending_keypairs.len(), 2);

        // Move past the pending duration, we should promote both pending keypairs.
        clock.advance(&pending_duration.add(&Duration::from_seconds(1)).unwrap());
        key_rotator.run().await.unwrap();
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let active_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Active)
            .collect();
        assert_eq!(active_keypairs.len(), 2);
        assert!(active_keypairs
            .iter()
            .find(|keypair| *keypair.id() == id)
            .is_some());

        // Step into the future, we should eventually replace both active keypairs with only one.
        for _ in 0..30 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }
        let keypairs = get_global_hpke_keypairs(&ds).await;
        let active_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Active)
            .collect();
        assert_eq!(active_keypairs.len(), 1);
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

        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuite: ciphersuite_0.clone(),
                retire: false,
            }]),
        );

        // Run the key rotator for a while.
        for _ in 0..18 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }

        // Operator inserts a new key in the active state.
        let id = HpkeConfigId::from(255);
        ds.run_unnamed_tx(|tx| {
            let ciphersuite_0 = ciphersuite_0.clone();
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
        assert_eq!(active_keypairs.len(), 2);

        // Step into the future, we should eventually replace both active keypairs with only one.
        for _ in 0..30 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }
        let keypairs = dbg!(get_global_hpke_keypairs(&ds).await);
        let active_keypairs: Vec<_> = keypairs
            .iter()
            .filter(|keypair| keypair.state() == &HpkeKeyState::Active)
            .collect();
        assert_eq!(active_keypairs.len(), 1);
    }

    #[tokio::test]
    async fn hpke_key_rotator_refuse_to_retire_only_one_key() {
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
            Vec::from([HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuite: ciphersuite_0.clone(),
                retire: true,
            }]),
        );

        assert!(key_rotator.run().await.is_err());

        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuite: ciphersuite_0.clone(),
                retire: false,
            }]),
        );

        for _ in 0..7 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }

        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([HpkeKeyRotatorConfig {
                pending_duration,
                active_duration,
                expired_duration,
                ciphersuite: ciphersuite_0.clone(),
                retire: true,
            }]),
        );

        assert!(key_rotator.run().await.is_err());
    }

    #[tokio::test]
    async fn hpke_key_rotator_retire() {
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

        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_0.clone(),
                    retire: false,
                },
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_1.clone(),
                    retire: false,
                },
            ]),
        );

        // Run the key rotator for a while, such that the current key is expired with one pending.
        for _ in 0..12 {
            key_rotator.run().await.unwrap();
            clock.advance(&Duration::from_seconds(30));
        }
        let keypairs = get_global_hpke_keypairs(&ds).await;
        assert_eq!(keypairs.len(), 4);

        // Retire ciphersuite_0.
        let key_rotator = KeyRotator::new(
            ds.clone(),
            Vec::from([
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_0.clone(),
                    retire: true,
                },
                HpkeKeyRotatorConfig {
                    pending_duration,
                    active_duration,
                    expired_duration,
                    ciphersuite: ciphersuite_1.clone(),
                    retire: false,
                },
            ]),
        );

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
