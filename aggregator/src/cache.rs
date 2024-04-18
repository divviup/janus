//! Various in-memory caches that can be used by an aggregator.

use crate::aggregator::{report_writer::ReportWriteBatcher, Error, TaskAggregator};
use janus_aggregator_core::{
    datastore::{models::HpkeKeyState, Datastore},
    taskprov::PeerAggregator,
};
use janus_core::{hpke::HpkeKeypair, time::Clock};
use janus_messages::{HpkeConfig, HpkeConfigId, Role, TaskId};
use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration as StdDuration, Instant},
};
use tokio::{spawn, sync::Mutex, task::JoinHandle, time::sleep};
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

    /// Create a `GlobalHpkeKeypairCacheView` with access to the same caches of configs and
    /// keypairs.
    pub fn view(&self) -> GlobalHpkeKeypairCacheView {
        GlobalHpkeKeypairCacheView {
            configs: Arc::clone(&self.configs),
            keypairs: Arc::clone(&self.keypairs),
        }
    }
}

impl Drop for GlobalHpkeKeypairCache {
    fn drop(&mut self) {
        self.refresh_handle.abort()
    }
}

#[derive(Debug)]
pub struct GlobalHpkeKeypairCacheView {
    // We use a std::sync::Mutex in this cache because we won't hold locks across
    // `.await` boundaries. StdMutex is lighter weight than `tokio::sync::Mutex`.
    /// Cache of HPKE configs for advertisement.
    configs: Arc<StdMutex<HpkeConfigs>>,

    /// Cache of HPKE keypairs for report decryption.
    keypairs: Arc<StdMutex<HpkeKeypairs>>,
}

impl GlobalHpkeKeypairCacheView {
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

pub struct TaskAggregatorCache<C: Clock> {
    datastore: Arc<Datastore<C>>,
    report_writer: Arc<ReportWriteBatcher<C>>,
    task_aggregators: StdMutex<HashMap<TaskId, Arc<Mutex<Option<Arc<TaskAggregator<C>>>>>>>,
}

impl<C: Clock> TaskAggregatorCache<C> {
    pub fn new(datastore: Arc<Datastore<C>>, report_writer: ReportWriteBatcher<C>) -> Self {
        Self {
            datastore,
            report_writer: Arc::new(report_writer),
            task_aggregators: Default::default(),
        }
    }

    pub async fn get(&self, task_id: &TaskId) -> Result<Option<Arc<TaskAggregator<C>>>, Error> {
        // TODO(#238): don't cache forever (decide on & implement some cache eviction policy). This
        // is important both to avoid ever-growing resource usage, and to allow aggregators to
        // notice when a task changes (e.g. due to key rotation).

        // Step one: grab the existing entry for this task, if one exists. If there is no existing
        // entry, write a new (empty) entry.
        let cache_entry = {
            // Unwrap safety: mutex poisoning.
            let mut task_aggs = self.task_aggregators.lock().unwrap();
            Arc::clone(
                task_aggs
                    .entry(*task_id)
                    .or_insert_with(|| Arc::new(Mutex::default())),
            )
        };

        // Step two: if the entry is empty, fill it via a database query. Concurrent callers
        // requesting the same task will contend over this lock while awaiting the result of the DB
        // query, ensuring that in the common case only a single query will be made for each task.
        let task_aggregator = {
            let mut cache_entry = cache_entry.lock().await;
            if cache_entry.is_none() {
                *cache_entry = self
                    .datastore
                    .run_tx("task_aggregator_get_task", |tx| {
                        let task_id = *task_id;
                        Box::pin(async move { tx.get_aggregator_task(&task_id).await })
                    })
                    .await?
                    .map(|task| TaskAggregator::new(task, Arc::clone(&self.report_writer)))
                    .transpose()?
                    .map(Arc::new);
            }
            cache_entry.as_ref().map(Arc::clone)
        };

        // If the task doesn't exist, remove the task entry from the cache to avoid caching a
        // negative result. Then return the result.
        //
        // TODO(#238): once cache eviction is implemented, we can likely remove this step. We only
        // need to do this to avoid trivial DoS via a requestor spraying many nonexistent task IDs.
        // However, we need to consider the taskprov case, where an aggregator can add a task and
        // expect it to be immediately visible.
        if task_aggregator.is_none() {
            // Unwrap safety: mutex poisoning.
            let mut task_aggs = self.task_aggregators.lock().unwrap();
            task_aggs.remove(task_id);
        }
        Ok(task_aggregator)
    }
}
