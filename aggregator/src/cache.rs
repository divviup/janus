//! Various in-memory caches that can be used by an aggregator.

use crate::aggregator::Error;
use janus_aggregator_core::{
    datastore::{models::HpkeKeyState, Datastore},
    taskprov::PeerAggregator,
};
use janus_core::{hpke::HpkeKeypair, time::Clock};
use janus_messages::{HpkeConfig, HpkeConfigId, Role};
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration as StdDuration, Instant},
};
use tokio::{spawn, task::JoinHandle, time::sleep};
use tracing::{debug, error};
use url::Url;

type HpkeConfigs = Arc<Vec<HpkeConfig>>;
type HpkeKeypairs = HashMap<HpkeConfigId, Arc<HpkeKeypair>>;

#[derive(Debug)]
pub struct GlobalHpkeKeypairCache {
    // We use a std::sync::Mutex in this cache because we won't hold locks across
    // `.await` boundaries. StdMutex is lighter weight than `tokio::sync::Mutex`.
    /// Cache of HPKE configs for advertisement.
    configs: Arc<StdMutex<HpkeConfigs>>,

    /// Cache of HPKE keypairs for report decryption.
    keypairs: Arc<StdMutex<HpkeKeypairs>>,

    /// Handle for task responsible for periodically refreshing the cache.
    refresh_handle: JoinHandle<()>,
}

impl GlobalHpkeKeypairCache {
    pub const DEFAULT_REFRESH_INTERVAL: StdDuration =
        StdDuration::from_secs(60 * 30 /* 30 minutes */);

    pub async fn new<C: Clock>(
        datastore: Arc<Datastore<C>>,
        refresh_interval: StdDuration,
    ) -> Result<Self, Error> {
        let keypairs = Arc::new(StdMutex::new(HashMap::new()));
        let configs = Arc::new(StdMutex::new(Arc::new(Vec::new())));

        // Initial cache load.
        Self::refresh_inner(&datastore, &configs, &keypairs).await?;

        // Start refresh task.
        let refresh_configs = configs.clone();
        let refresh_keypairs = keypairs.clone();
        let refresh_datastore = datastore.clone();
        let refresh_handle = spawn(async move {
            loop {
                sleep(refresh_interval).await;

                let now = Instant::now();
                let result =
                    Self::refresh_inner(&refresh_datastore, &refresh_configs, &refresh_keypairs)
                        .await;
                let elapsed = now.elapsed();

                match result {
                    Ok(_) => debug!(?elapsed, "successfully refreshed HPKE keypair cache"),
                    Err(err) => error!(?err, ?elapsed, "failed to refresh HPKE keypair cache"),
                }
            }
        });

        Ok(Self {
            configs,
            keypairs,
            refresh_handle,
        })
    }

    async fn refresh_inner<C: Clock>(
        datastore: &Datastore<C>,
        configs: &StdMutex<HpkeConfigs>,
        keypairs: &StdMutex<HpkeKeypairs>,
    ) -> Result<(), Error> {
        let global_keypairs = datastore
            .run_tx("refresh_global_hpke_keypairs_cache", |tx| {
                Box::pin(async move { tx.get_global_hpke_keypairs().await })
            })
            .await?;

        let new_configs = Arc::new(
            global_keypairs
                .iter()
                .filter_map(|keypair| match keypair.state() {
                    HpkeKeyState::Active => Some(keypair.hpke_keypair().config().clone()),
                    _ => None,
                })
                .collect(),
        );

        let new_keypairs = global_keypairs
            .iter()
            .map(|keypair| {
                let keypair = keypair.hpke_keypair().clone();
                (*keypair.config().id(), Arc::new(keypair))
            })
            .collect();

        {
            let mut configs = configs.lock().unwrap();
            *configs = new_configs;
        }
        {
            let mut keypairs = keypairs.lock().unwrap();
            *keypairs = new_keypairs;
        }
        Ok(())
    }

    #[cfg(feature = "test-util")]
    pub async fn refresh<C: Clock>(&self, datastore: &Datastore<C>) -> Result<(), Error> {
        Self::refresh_inner(datastore, &self.configs, &self.keypairs).await
    }

    /// Retrieve active configs for config advertisement. This only returns configs
    /// for keypairs that are in the `[HpkeKeyState::Active]` state.
    pub fn configs(&self) -> HpkeConfigs {
        let configs = self.configs.lock().unwrap();
        configs.clone()
    }

    /// Retrieve a keypair by ID for report decryption. This retrieves keypairs that
    /// are in any state.
    pub fn keypair(&self, id: &HpkeConfigId) -> Option<Arc<HpkeKeypair>> {
        let keypairs = self.keypairs.lock().unwrap();
        keypairs.get(id).cloned()
    }
}

impl Drop for GlobalHpkeKeypairCache {
    fn drop(&mut self) {
        self.refresh_handle.abort()
    }
}

/// Caches taskprov [`PeerAggregator`]'s. This cache is never invalidated, so the process needs to
/// be restarted if there are any changes to peer aggregators.
#[derive(Debug)]
pub struct PeerAggregatorCache {
    peers: Vec<PeerAggregator>,
}

impl PeerAggregatorCache {
    pub async fn new<C: Clock>(datastore: &Datastore<C>) -> Result<Self, Error> {
        Ok(Self {
            peers: datastore
                .run_tx("refresh_peer_aggregators_cache", |tx| {
                    Box::pin(async move { tx.get_taskprov_peer_aggregators().await })
                })
                .await?
                .into_iter()
                .collect(),
        })
    }

    pub fn get(&self, endpoint: &Url, role: &Role) -> Option<&PeerAggregator> {
        // The peer aggregator table is unlikely to be more than a few entries long (1-2 entries),
        // so a linear search should be fine.
        self.peers
            .iter()
            .find(|peer| peer.endpoint() == endpoint && peer.role() == role)
    }
}
