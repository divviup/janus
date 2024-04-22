//! Various in-memory caches that can be used by an aggregator.

use crate::aggregator::{report_writer::ReportWriteBatcher, Error, TaskAggregator};
use janus_aggregator_core::{
    datastore::{models::HpkeKeyState, Datastore},
    taskprov::PeerAggregator,
};
use janus_core::{
    hpke::HpkeKeypair,
    time::{Clock, TimeExt},
};
use janus_messages::{Duration, HpkeConfig, HpkeConfigId, Role, TaskId, Time};
use rand::{distributions::Uniform, thread_rng, Rng};
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

#[derive(Debug)]
pub struct TaskAggregatorCache<C: Clock> {
    clock: C,
    datastore: Arc<Datastore<C>>,
    report_writer: Arc<ReportWriteBatcher<C>>,
    entries: StdMutex<HashMap<TaskId, TaskAggregatorCacheEntry<C>>>,
    cache_none: bool,
    ttl_seconds: Uniform<u64>,
}

type TaskAggregatorCacheEntry<C> = Arc<Mutex<TaskAggregatorCacheEntryContents<C>>>;

#[derive(Debug)]
struct TaskAggregatorCacheEntryContents<C: Clock> {
    /// When the entry expires.
    expiration: Time,
    /// The outer Option is None when the task_aggregator hasn't been initialized yet.
    task_aggregator: Option<TaskAggregatorRef<C>>,
}

type TaskAggregatorRef<C> = Option<Arc<TaskAggregator<C>>>;

pub const TASK_AGGREGATOR_CACHE_DEFAULT_TTL: Duration = Duration::from_seconds(600);

impl<C: Clock> TaskAggregatorCache<C> {
    pub fn new(
        clock: C,
        datastore: Arc<Datastore<C>>,
        report_writer: ReportWriteBatcher<C>,
        cache_none: bool,
        ttl: Duration,
    ) -> Self {
        let ttl = ttl.as_seconds();
        // We don't need this to be precise, so floating point truncation is acceptable.
        let jitter = (ttl as f64 * 0.1) as u64;
        Self {
            clock,
            datastore,
            report_writer: Arc::new(report_writer),
            entries: Default::default(),
            cache_none,
            ttl_seconds: Uniform::new(ttl - jitter, ttl + jitter),
        }
    }

    /// Calculates the next possible cache TTL. This contains jitter to prevent all tasks in the
    /// cache from falling on the same deadline on application startup.
    fn next_ttl(&self) -> Time {
        self.clock.now().saturating_add(&Duration::from_seconds(
            thread_rng().sample(self.ttl_seconds),
        ))
    }

    pub async fn get(&self, task_id: &TaskId) -> Result<TaskAggregatorRef<C>, Error> {
        // Step one: grab the existing entry for this task, if one exists. If there is no existing
        // entry, write a new uninitialized entry.
        let entry = {
            // Unwrap safety: mutex poisoning.
            let mut entries = self.entries.lock().unwrap();
            Arc::clone(entries.entry(*task_id).or_insert(Arc::new(Mutex::new(
                TaskAggregatorCacheEntryContents {
                    expiration: self.next_ttl(),
                    task_aggregator: None,
                },
            ))))
        };

        // Step two: if the entry is uninitialized or expired, fill it via a database query. Concurrent
        // callers requesting the same task will contend over this lock while awaiting the result of
        // the DB query, ensuring that in the common case only a single query will be made for each
        // task.
        let task_aggregator = {
            let mut entry = entry.lock().await;
            if self.clock.now() > entry.expiration || entry.task_aggregator.is_none() {
                *entry = TaskAggregatorCacheEntryContents {
                    expiration: self.next_ttl(),
                    task_aggregator: Some(
                        self.datastore
                            .run_tx("task_aggregator_get_task", |tx| {
                                let task_id = *task_id;
                                Box::pin(async move { tx.get_aggregator_task(&task_id).await })
                            })
                            .await?
                            .map(|task| TaskAggregator::new(task, Arc::clone(&self.report_writer)))
                            .transpose()?
                            .map(Arc::new),
                    ),
                };
            }
            // Unwrap safety: we've ensured that the entry is initialized in the previous if statement.
            entry
                .task_aggregator
                .as_ref()
                .unwrap()
                .as_ref()
                .map(|entry| Arc::clone(&entry))
        };

        if !self.cache_none && task_aggregator.is_none() {
            // Unwrap safety: mutex poisoning.
            let mut task_aggs = self.entries.lock().unwrap();
            task_aggs.remove(task_id);
        }

        Ok(task_aggregator)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration as StdDuration};

    use janus_aggregator_core::{
        datastore::test_util::ephemeral_datastore,
        task::{test_util::TaskBuilder, QueryType},
    };
    use janus_core::{
        test_util::{install_test_trace_subscriber, runtime::TestRuntime},
        time::MockClock,
        vdaf::VdafInstance,
    };
    use janus_messages::{Duration, Time};

    use crate::{aggregator::report_writer::ReportWriteBatcher, cache::TaskAggregatorCache};

    #[tokio::test]
    async fn task_aggregator() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let ttl = Duration::from_seconds(600);
        let task_aggregators = TaskAggregatorCache::new(
            clock.clone(),
            Arc::clone(&datastore),
            ReportWriteBatcher::new(
                Arc::clone(&datastore),
                TestRuntime::default(),
                100,                         // doesn't matter
                100,                         // doesn't matter
                StdDuration::from_secs(100), // doesn't matter
            ),
            false,
            ttl,
        );

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .build()
            .leader_view()
            .unwrap();

        assert!(task_aggregators.get(task.id()).await.unwrap().is_none());
        // We shouldn't have cached that last call.
        assert!(task_aggregators.entries.lock().unwrap().is_empty());

        // A wild task appears!
        datastore.put_aggregator_task(&task).await.unwrap();
        let task_aggregator = task_aggregators.get(task.id()).await.unwrap().unwrap();
        assert_eq!(task_aggregator.task.id(), task.id());

        // Modify the task.
        let new_expiration = Time::from_seconds_since_epoch(100);
        datastore
            .run_unnamed_tx(|tx| {
                let task_id = *task.id();
                Box::pin(async move {
                    tx.update_task_expiration(&task_id, Some(&new_expiration))
                        .await
                        .unwrap();
                    Ok(())
                })
            })
            .await
            .unwrap();

        // That change shouldn't be reflected yet because we've cached the previous task.
        let task_aggregator = task_aggregators.get(task.id()).await.unwrap().unwrap();
        assert_eq!(
            task_aggregator.task.task_expiration(),
            task.task_expiration()
        );

        clock.advance(&ttl);
        clock.advance(&ttl);

        let task_aggregator = task_aggregators.get(task.id()).await.unwrap().unwrap();
        assert_eq!(
            task_aggregator.task.task_expiration(),
            Some(&new_expiration)
        );
    }

    #[tokio::test]
    async fn task_aggregator_cache_none() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(clock.clone()).await);

        let ttl = Duration::from_seconds(600);
        let task_aggregators = TaskAggregatorCache::new(
            clock.clone(),
            Arc::clone(&datastore),
            ReportWriteBatcher::new(
                Arc::clone(&datastore),
                TestRuntime::default(),
                100,                         // doesn't matter
                100,                         // doesn't matter
                StdDuration::from_secs(100), // doesn't matter
            ),
            true,
            ttl,
        );

        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Prio3Count)
            .build()
            .leader_view()
            .unwrap();

        assert!(task_aggregators.get(task.id()).await.unwrap().is_none());

        // A wild task appears!
        datastore.put_aggregator_task(&task).await.unwrap();

        // We shouldn't see the new task yet.
        assert!(task_aggregators.get(task.id()).await.unwrap().is_none());

        clock.advance(&ttl);
        clock.advance(&ttl);

        // Now we should see it.
        let task_aggregator = task_aggregators.get(task.id()).await.unwrap().unwrap();
        assert_eq!(task_aggregator.task.id(), task.id());

        // Modify the task.
        let new_expiration = Time::from_seconds_since_epoch(100);
        datastore
            .run_unnamed_tx(|tx| {
                let task_id = *task.id();
                Box::pin(async move {
                    tx.update_task_expiration(&task_id, Some(&new_expiration))
                        .await
                        .unwrap();
                    Ok(())
                })
            })
            .await
            .unwrap();

        // That change shouldn't be reflected yet because we've cached the previous run.
        let task_aggregator = task_aggregators.get(task.id()).await.unwrap().unwrap();
        assert_eq!(
            task_aggregator.task.task_expiration(),
            task.task_expiration()
        );

        clock.advance(&ttl);
        clock.advance(&ttl);

        let task_aggregator = task_aggregators.get(task.id()).await.unwrap().unwrap();
        assert_eq!(
            task_aggregator.task.task_expiration(),
            Some(&new_expiration)
        );
    }
}
