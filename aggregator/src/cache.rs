use janus_aggregator_core::datastore::{
    models::{GlobalHpkeKeypair, HpkeKeyState},
    Datastore,
};

use janus_core::{hpke::HpkeKeypair, time::Clock};
use janus_messages::{HpkeConfig, HpkeConfigId};

use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex as StdMutex},
    time::Duration as StdDuration,
};
use tokio::{spawn, task::JoinHandle, time::sleep};
use tracing::error;

use crate::aggregator::Error;

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
        // Initial cache load.
        let global_keypairs = Self::get_global_keypairs(&datastore).await?;
        let configs = Arc::new(StdMutex::new(Self::filter_active_configs(&global_keypairs)));
        let keypairs = Arc::new(StdMutex::new(Self::map_keypairs(&global_keypairs)));

        // Start refresh task.
        let refresh_configs = configs.clone();
        let refresh_keypairs = keypairs.clone();
        let refresh_handle = spawn(async move {
            loop {
                sleep(refresh_interval).await;

                match Self::get_global_keypairs(&datastore).await {
                    Ok(global_keypairs) => {
                        let new_configs = Self::filter_active_configs(&global_keypairs);
                        let new_keypairs = Self::map_keypairs(&global_keypairs);
                        {
                            let mut configs = refresh_configs.lock().unwrap();
                            *configs = new_configs;
                        }
                        {
                            let mut keypairs = refresh_keypairs.lock().unwrap();
                            *keypairs = new_keypairs;
                        }
                    }
                    Err(err) => {
                        error!(?err, "failed to refresh HPKE config cache");
                    }
                }
            }
        });

        Ok(Self {
            configs,
            keypairs,
            refresh_handle,
        })
    }

    fn filter_active_configs(global_keypairs: &[GlobalHpkeKeypair]) -> HpkeConfigs {
        Arc::new(
            global_keypairs
                .iter()
                .filter_map(|keypair| match keypair.state() {
                    HpkeKeyState::Active => Some(keypair.hpke_keypair().config().clone()),
                    _ => None,
                })
                .collect(),
        )
    }

    fn map_keypairs(global_keypairs: &[GlobalHpkeKeypair]) -> HpkeKeypairs {
        global_keypairs
            .iter()
            .map(|keypair| {
                let keypair = keypair.hpke_keypair().clone();
                (*keypair.config().id(), Arc::new(keypair))
            })
            .collect()
    }

    async fn get_global_keypairs<C: Clock>(
        datastore: &Datastore<C>,
    ) -> Result<Vec<GlobalHpkeKeypair>, Error> {
        Ok(datastore
            .run_tx_with_name("refresh_global_hpke_configs_cache", |tx| {
                Box::pin(async move { tx.get_global_hpke_keypairs().await })
            })
            .await?)
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
