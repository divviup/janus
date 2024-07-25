//! Common functionality for DAP aggregators.

pub use crate::aggregator::error::Error;
use crate::{
    aggregator::{
        aggregate_share::compute_aggregate_share,
        aggregation_job_writer::{
            AggregationJobWriter, AggregationJobWriterMetrics, InitialWrite,
            ReportAggregationUpdate as _, WritableReportAggregation,
        },
        error::{
            handle_ping_pong_error, BatchMismatch, OptOutReason, ReportRejection,
            ReportRejectionReason,
        },
        query_type::{CollectableQueryType, UploadableQueryType},
        report_writer::{ReportWriteBatcher, WritableReport},
    },
    cache::{
        GlobalHpkeKeypairCache, PeerAggregatorCache, TaskAggregatorCache,
        TASK_AGGREGATOR_CACHE_DEFAULT_CAPACITY, TASK_AGGREGATOR_CACHE_DEFAULT_TTL,
    },
    config::TaskprovConfig,
    diagnostic::AggregationJobInitForbiddenMutationEvent,
    metrics::{
        aggregate_step_failure_counter, aggregated_report_share_dimension_histogram,
        report_aggregation_success_counter,
    },
};
use backoff::{backoff::Backoff, Notify};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{
    types::extra::{U15, U31},
    FixedI16, FixedI32,
};
use futures::future::try_join_all;
use http::{header::CONTENT_TYPE, Method};
use itertools::iproduct;
use janus_aggregator_core::{
    datastore::{
        self,
        models::{
            AggregateShareJob, AggregationJob, AggregationJobState, BatchAggregation,
            BatchAggregationState, CollectionJob, CollectionJobState, LeaderStoredReport,
            ReportAggregation, ReportAggregationState, TaskAggregationCounter,
        },
        Datastore, Error as DatastoreError, Transaction,
    },
    query_type::AccumulableQueryType,
    task::{self, AggregatorTask, VerifyKey},
    taskprov::PeerAggregator,
};
#[cfg(feature = "fpvec_bounded_l2")]
use janus_core::vdaf::Prio3FixedPointBoundedL2VecSumBitSize;
use janus_core::{
    auth_tokens::AuthenticationToken,
    hpke::{self, HpkeApplicationInfo, HpkeKeypair, Label},
    retries::retry_http_request_notify,
    time::{Clock, DurationExt, IntervalExt, TimeExt},
    vdaf::{
        new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128,
        Prio3SumVecField64MultiproofHmacSha256Aes128, VdafInstance, VERIFY_KEY_LENGTH,
    },
    Runtime,
};
use janus_messages::{
    query_type::{FixedSize, TimeInterval},
    taskprov::{DpMechanism, TaskConfig},
    AggregateShare, AggregateShareAad, AggregateShareReq, AggregationJobContinueReq,
    AggregationJobId, AggregationJobInitializeReq, AggregationJobResp, AggregationJobStep,
    BatchSelector, Collection, CollectionJobId, CollectionReq, Duration, ExtensionType, HpkeConfig,
    HpkeConfigList, InputShareAad, Interval, PartialBatchSelector, PlaintextInputShare,
    PrepareError, PrepareResp, PrepareStepResult, Report, ReportIdChecksum, ReportShare, Role,
    TaskId,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter},
    KeyValue,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSum;
#[cfg(feature = "test-util")]
use prio::vdaf::{dummy, PrepareTransition, VdafError};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    dp::DifferentialPrivacyStrategy,
    field::Field64,
    flp::gadgets::{Mul, ParallelSum},
    topology::ping_pong::{PingPongState, PingPongTopology},
    vdaf::{
        self,
        poplar1::Poplar1,
        prio3::{Prio3, Prio3Count, Prio3Histogram, Prio3Sum, Prio3SumVec},
        xof::XofTurboShake128,
    },
};
use rand::{thread_rng, Rng};
use rayon::iter::{IndexedParallelIterator as _, IntoParallelRefIterator as _, ParallelIterator};
use reqwest::Client;
use ring::{
    digest::{digest, SHA256},
    rand::SystemRandom,
    signature::{EcdsaKeyPair, Signature},
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    panic,
    path::PathBuf,
    sync::{Arc, Mutex as SyncMutex},
    time::{Duration as StdDuration, Instant},
};
use tokio::{sync::mpsc, try_join};
use tracing::{debug, error, info, info_span, trace_span, warn, Level, Span};
use url::Url;

#[cfg(test)]
mod aggregate_init_tests;
pub mod aggregate_share;
pub mod aggregation_job_continue;
pub mod aggregation_job_creator;
pub mod aggregation_job_driver;
pub mod aggregation_job_writer;
pub mod batch_creator;
pub mod collection_job_driver;
#[cfg(test)]
mod collection_job_tests;
mod error;
pub mod garbage_collector;
pub mod http_handlers;
pub mod key_rotator;
pub mod problem_details;
pub mod query_type;
pub mod report_writer;
#[cfg(test)]
mod taskprov_tests;
#[cfg(feature = "test-util")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-util")))]
pub mod test_util;
#[cfg(test)]
mod upload_tests;

/// Aggregator implements a DAP aggregator.
pub struct Aggregator<C: Clock> {
    /// Datastore used for durable storage.
    datastore: Arc<Datastore<C>>,
    /// Clock used to sample time.
    clock: C,
    /// Configuration used for this aggregator.
    cfg: Config,
    /// Cache of task aggregators.
    task_aggregators: TaskAggregatorCache<C>,
    /// Metrics.
    metrics: AggregatorMetrics,

    /// Cache of global HPKE keypairs and configs.
    global_hpke_keypairs: GlobalHpkeKeypairCache,

    /// Cache of taskprov peer aggregators.
    peer_aggregators: PeerAggregatorCache,
}

#[derive(Clone)]
struct AggregatorMetrics {
    /// Counter tracking the number of failed decryptions while handling the
    /// `tasks/{task-id}/reports` endpoint.
    upload_decrypt_failure_counter: Counter<u64>,
    /// Counter tracking the number of failed message decodes while handling the
    /// `tasks/{task-id}/reports` endpoint.
    upload_decode_failure_counter: Counter<u64>,
    /// Counter tracking the number of successfully-aggregated reports.
    report_aggregation_success_counter: Counter<u64>,
    /// Counters tracking the number of failures to step client reports through the aggregation
    /// process.
    aggregate_step_failure_counter: Counter<u64>,
    /// Histogram tracking the VDAF type and dimension of successfully-aggregated reports.
    aggregated_report_share_dimension_histogram: Histogram<u64>,
}

impl AggregatorMetrics {
    fn for_aggregation_job_writer(&self) -> AggregationJobWriterMetrics {
        AggregationJobWriterMetrics {
            report_aggregation_success_counter: self.report_aggregation_success_counter.clone(),
            aggregate_step_failure_counter: self.aggregate_step_failure_counter.clone(),
            aggregated_report_share_dimension_histogram: self
                .aggregated_report_share_dimension_histogram
                .clone(),
        }
    }
}

/// Config represents a configuration for an Aggregator.
#[derive(Debug)]
pub struct Config {
    /// Defines the maximum size of a batch of uploaded reports which will be written in a single
    /// transaction.
    pub max_upload_batch_size: usize,

    /// Defines the maximum delay before writing a batch of uploaded reports, even if it has not yet
    /// reached `max_batch_upload_size`. This is the maximum delay added to the
    /// `tasks/{task-id}/reports` endpoint due to write-batching.
    pub max_upload_batch_write_delay: StdDuration,

    /// Defines the number of shards to break each batch aggregation into. Increasing this value
    /// will reduce the amount of database contention during helper aggregation, while increasing
    /// the cost of collection.
    pub batch_aggregation_shard_count: u64,

    /// Defines the number of shards to break report counters into. Increasing this value will
    /// reduce the amount of database contention during report uploads, while increasing the cost
    /// of getting task metrics.
    pub task_counter_shard_count: u64,

    /// Defines how often to refresh the global HPKE configs cache. This affects how often an aggregator
    /// becomes aware of key state changes.
    pub global_hpke_configs_refresh_interval: StdDuration,

    /// Defines how long tasks should be cached for. This affects how often an aggregator becomes aware
    /// of task parameter changes.
    pub task_cache_ttl: StdDuration,

    /// Defines how many tasks can be cached at once. This affects how much memory the aggregator may
    /// consume for caching tasks.
    pub task_cache_capacity: u64,

    /// The key used to sign HPKE configurations.
    pub hpke_config_signing_key: Option<EcdsaKeyPair>,

    /// Configuration for the taskprov extension.
    pub taskprov_config: TaskprovConfig,

    /// If set, forbidden mutations of resources (e.g., re-using the same aggregation job ID but
    /// with different reports in it) will be logged to files under this path when detected.
    ///
    /// This option is not stable, and not subject to Janus' typical API/config stability promises.
    pub log_forbidden_mutations: Option<PathBuf>,

    // If set, always prefer to advertise global HPKE keys. This is implicitly enabled if taskprov
    // is enabled.
    //
    // This will become on by default in a future version of Janus.
    pub require_global_hpke_keys: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_upload_batch_size: 1,
            max_upload_batch_write_delay: StdDuration::ZERO,
            batch_aggregation_shard_count: 1,
            task_counter_shard_count: 32,
            global_hpke_configs_refresh_interval: GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL,
            hpke_config_signing_key: None,
            taskprov_config: TaskprovConfig::default(),
            task_cache_ttl: TASK_AGGREGATOR_CACHE_DEFAULT_TTL,
            task_cache_capacity: TASK_AGGREGATOR_CACHE_DEFAULT_CAPACITY,
            log_forbidden_mutations: None,
            require_global_hpke_keys: true,
        }
    }
}

impl<C: Clock> Aggregator<C> {
    /// Creates a new [`Aggregator`].
    ///
    /// # Errors
    ///
    /// Fails on general datastore errors.
    ///
    /// If [`Self::require_global_hpke_keys`] is `true`, and there is not at least one
    /// [`GlobalHpkeKeypair`] in the database in the [`HpkeKeyState::Active`] state then this
    /// function will fail.
    async fn new<R: Runtime + Send + Sync + 'static>(
        datastore: Arc<Datastore<C>>,
        clock: C,
        runtime: R,
        meter: &Meter,
        cfg: Config,
    ) -> Result<Self, Error> {
        let task_aggregators = TaskAggregatorCache::new(
            Arc::clone(&datastore),
            ReportWriteBatcher::new(
                Arc::clone(&datastore),
                runtime,
                cfg.task_counter_shard_count,
                cfg.max_upload_batch_size,
                cfg.max_upload_batch_write_delay,
            ),
            // If we're in taskprov mode, we can never cache None entries for tasks, since aggregators
            // could insert tasks at any time and expect them to be available across all aggregator
            // replicas.
            !cfg.taskprov_config.enabled,
            cfg.task_cache_capacity,
            cfg.task_cache_ttl,
        );

        let upload_decrypt_failure_counter = meter
            .u64_counter("janus_upload_decrypt_failures")
            .with_description(
                "Number of decryption failures in the tasks/{task-id}/reports endpoint.",
            )
            .with_unit("{error}")
            .init();
        upload_decrypt_failure_counter.add(0, &[]);

        let upload_decode_failure_counter = meter
            .u64_counter("janus_upload_decode_failures")
            .with_description(
                "Number of message decode failures in the tasks/{task-id}/reports endpoint.",
            )
            .with_unit("{error}")
            .init();
        upload_decode_failure_counter.add(0, &[]);

        let report_aggregation_success_counter = report_aggregation_success_counter(meter);
        let aggregate_step_failure_counter = aggregate_step_failure_counter(meter);
        let aggregated_report_share_dimension_histogram =
            aggregated_report_share_dimension_histogram(meter);

        let global_hpke_keypairs = GlobalHpkeKeypairCache::new(
            datastore.clone(),
            cfg.global_hpke_configs_refresh_interval,
            cfg.require_global_hpke_keys || cfg.taskprov_config.enabled,
        )
        .await?;

        let peer_aggregators = PeerAggregatorCache::new(&datastore).await?;

        Ok(Self {
            datastore,
            clock,
            cfg,
            task_aggregators,
            metrics: AggregatorMetrics {
                upload_decrypt_failure_counter,
                upload_decode_failure_counter,
                report_aggregation_success_counter,
                aggregate_step_failure_counter,
                aggregated_report_share_dimension_histogram,
            },
            global_hpke_keypairs,
            peer_aggregators,
        })
    }

    /// Handles an HPKE config request.
    ///
    /// The returned value is the encoded HPKE config list (i.e. the response body), and an optional
    /// signature over the body if the aggregator is configured to sign HPKE config responses.
    async fn handle_hpke_config(
        &self,
        task_id_base64: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Option<Signature>), Error> {
        // Retrieve the appropriate HPKE config list.
        let hpke_config_list =
            if self.cfg.taskprov_config.enabled || self.cfg.require_global_hpke_keys {
                // If we're running in taskprov mode or requiring global keys, unconditionally
                // provide the global keys and ignore the task_id parameter.
                let configs = self.global_hpke_keypairs.configs();
                if configs.is_empty() {
                    return Err(Error::Internal(
                        "this server is missing its global HPKE config".into(),
                    ));
                } else {
                    HpkeConfigList::new(configs.to_vec())
                }
            } else {
                // Otherwise, try to get the task-specific key.
                match task_id_base64 {
                    Some(task_id_base64) => {
                        let task_id_bytes = URL_SAFE_NO_PAD
                            .decode(task_id_base64)
                            .map_err(|_| Error::InvalidMessage(None, "task_id"))?;
                        let task_id = TaskId::get_decoded(&task_id_bytes)
                            .map_err(|_| Error::InvalidMessage(None, "task_id"))?;
                        let task_aggregator = self
                            .task_aggregators
                            .get(&task_id)
                            .await?
                            .ok_or(Error::UnrecognizedTask(task_id))?;

                        match task_aggregator.handle_hpke_config() {
                            Some(hpke_config_list) => hpke_config_list,
                            // Assuming something hasn't gone horribly wrong with the database, this
                            // should only happen in the case where the system has been moved from taskprov
                            // mode to non-taskprov mode. Thus there's still taskprov tasks in the database.
                            // This isn't a supported use case, so the operator needs to delete these tasks
                            // or move the system back into taskprov mode.
                            None => {
                                return Err(Error::Internal("task has no HPKE configs".to_string()))
                            }
                        }
                    }
                    // No task ID present, try to fall back to a global config.
                    None => {
                        let configs = self.global_hpke_keypairs.configs();
                        if configs.is_empty() {
                            // This server isn't configured to provide global HPKE keys, the client
                            // should have given us a task ID.
                            return Err(Error::MissingTaskId);
                        } else {
                            HpkeConfigList::new(configs.to_vec())
                        }
                    }
                }
            };

        // Encode & (if configured to do so) sign the HPKE config list.
        let encoded_hpke_config_list = hpke_config_list
            .get_encoded()
            .map_err(Error::MessageEncode)?;
        let signature = self
            .cfg
            .hpke_config_signing_key
            .as_ref()
            .map(|key| key.sign(&SystemRandom::new(), &encoded_hpke_config_list))
            .transpose()
            .map_err(|_| Error::Internal("hpke config list signing error".to_string()))?;

        Ok((encoded_hpke_config_list, signature))
    }

    async fn handle_upload(&self, task_id: &TaskId, report_bytes: &[u8]) -> Result<(), Arc<Error>> {
        let report =
            Report::get_decoded(report_bytes).map_err(|err| Arc::new(Error::MessageDecode(err)))?;

        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Arc::new(Error::UnrecognizedTask(*task_id)));
        }
        task_aggregator
            .handle_upload(
                &self.clock,
                &self.global_hpke_keypairs,
                &self.metrics,
                report,
            )
            .await
    }

    async fn handle_aggregate_init(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
        taskprov_task_config: Option<&TaskConfig>,
    ) -> Result<AggregationJobResp, Error> {
        let task_aggregator = match self.task_aggregators.get(task_id).await? {
            Some(task_aggregator) => {
                if task_aggregator.task.role() != &Role::Helper {
                    return Err(Error::UnrecognizedTask(*task_id));
                }
                if self.cfg.taskprov_config.enabled && taskprov_task_config.is_some() {
                    self.taskprov_authorize_request(
                        &Role::Leader,
                        task_id,
                        taskprov_task_config.unwrap(),
                        auth_token.as_ref(),
                    )
                    .await?;
                } else if !task_aggregator
                    .task
                    .check_aggregator_auth_token(auth_token.as_ref())
                {
                    return Err(Error::UnauthorizedRequest(*task_id));
                }
                task_aggregator
            }
            None if self.cfg.taskprov_config.enabled && taskprov_task_config.is_some() => {
                self.taskprov_opt_in(
                    &Role::Leader,
                    task_id,
                    taskprov_task_config.unwrap(),
                    auth_token.as_ref(),
                )
                .await?;

                // Retry fetching the aggregator, since the last function would have just inserted
                // its task.
                debug!(
                    ?task_id,
                    "taskprov: opt-in successful, retrying task acquisition"
                );
                self.task_aggregators.get(task_id).await?.ok_or_else(|| {
                    Error::Internal("unexpectedly failed to create task".to_string())
                })?
            }
            _ => {
                return Err(Error::UnrecognizedTask(*task_id));
            }
        };

        task_aggregator
            .handle_aggregate_init(
                Arc::clone(&self.datastore),
                &self.clock,
                &self.global_hpke_keypairs,
                &self.metrics,
                self.cfg.batch_aggregation_shard_count,
                self.cfg.task_counter_shard_count,
                aggregation_job_id,
                taskprov_task_config.is_some(),
                self.cfg.log_forbidden_mutations.clone(),
                req_bytes,
            )
            .await
    }

    async fn handle_aggregate_continue(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
        taskprov_task_config: Option<&TaskConfig>,
    ) -> Result<AggregationJobResp, Error> {
        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(*task_id));
        }

        if self.cfg.taskprov_config.enabled && taskprov_task_config.is_some() {
            self.taskprov_authorize_request(
                &Role::Leader,
                task_id,
                taskprov_task_config.unwrap(),
                auth_token.as_ref(),
            )
            .await?;
        } else if !task_aggregator
            .task
            .check_aggregator_auth_token(auth_token.as_ref())
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        let req =
            AggregationJobContinueReq::get_decoded(req_bytes).map_err(Error::MessageDecode)?;
        // unwrap safety: SHA-256 computed by ring should always be 32 bytes
        let request_hash = digest(&SHA256, req_bytes).as_ref().try_into().unwrap();

        task_aggregator
            .handle_aggregate_continue(
                Arc::clone(&self.datastore),
                &self.metrics,
                self.cfg.batch_aggregation_shard_count,
                self.cfg.task_counter_shard_count,
                aggregation_job_id,
                req,
                request_hash,
            )
            .await
    }

    async fn handle_aggregate_delete(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        auth_token: Option<AuthenticationToken>,
        taskprov_task_config: Option<&TaskConfig>,
    ) -> Result<(), Error> {
        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(*task_id));
        }

        if self.cfg.taskprov_config.enabled && taskprov_task_config.is_some() {
            self.taskprov_authorize_request(
                &Role::Leader,
                task_id,
                taskprov_task_config.unwrap(),
                auth_token.as_ref(),
            )
            .await?;
        } else if !task_aggregator
            .task
            .check_aggregator_auth_token(auth_token.as_ref())
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_aggregate_delete(&self.datastore, aggregation_job_id)
            .await
    }

    /// Handle a collection job creation request. Only supported by the leader. `req_bytes` is an
    /// encoded [`CollectionReq`].
    async fn handle_create_collection_job(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
    ) -> Result<(), Error> {
        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !task_aggregator
            .task
            .check_collector_auth_token(auth_token.as_ref())
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_create_collection_job(&self.datastore, collection_job_id, req_bytes)
            .await
    }

    /// Handle a GET request for a collection job. `collection_job_id` is the unique identifier for the
    /// collection job parsed out of the request URI. Returns an encoded [`Collection`] if the collect
    /// job has been run to completion, `None` if the collection job has not yet run, or an error
    /// otherwise.
    async fn handle_get_collection_job(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
        auth_token: Option<AuthenticationToken>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !task_aggregator
            .task
            .check_collector_auth_token(auth_token.as_ref())
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_get_collection_job(&self.datastore, collection_job_id)
            .await
    }

    /// Handle a DELETE request for a collection job.
    async fn handle_delete_collection_job(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
        auth_token: Option<AuthenticationToken>,
    ) -> Result<(), Error> {
        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Leader {
            return Err(Error::UnrecognizedTask(*task_id));
        }
        if !task_aggregator
            .task
            .check_collector_auth_token(auth_token.as_ref())
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        task_aggregator
            .handle_delete_collection_job(&self.datastore, collection_job_id)
            .await?;

        Ok(())
    }

    /// Handle an aggregate share request. Only supported by the helper. `req_bytes` is an encoded
    /// [`AggregateShareReq`]. Returns an [`AggregateShare`].
    async fn handle_aggregate_share(
        &self,
        task_id: &TaskId,
        req_bytes: &[u8],
        auth_token: Option<AuthenticationToken>,
        taskprov_task_config: Option<&TaskConfig>,
    ) -> Result<AggregateShare, Error> {
        let task_aggregator = self
            .task_aggregators
            .get(task_id)
            .await?
            .ok_or(Error::UnrecognizedTask(*task_id))?;
        if task_aggregator.task.role() != &Role::Helper {
            return Err(Error::UnrecognizedTask(*task_id));
        }

        // Authorize the request and retrieve the collector's HPKE config. If this is a taskprov task, we
        // have to use the peer aggregator's collector config rather than the main task.
        let collector_hpke_config =
            if self.cfg.taskprov_config.enabled && taskprov_task_config.is_some() {
                let (peer_aggregator, _, _) = self
                    .taskprov_authorize_request(
                        &Role::Leader,
                        task_id,
                        taskprov_task_config.unwrap(),
                        auth_token.as_ref(),
                    )
                    .await?;

                peer_aggregator.collector_hpke_config()
            } else {
                if !task_aggregator
                    .task
                    .check_aggregator_auth_token(auth_token.as_ref())
                {
                    return Err(Error::UnauthorizedRequest(*task_id));
                }

                task_aggregator
                    .task
                    .collector_hpke_config()
                    .ok_or_else(|| {
                        Error::Internal("task is missing collector_hpke_config".to_string())
                    })?
            };

        task_aggregator
            .handle_aggregate_share(
                &self.datastore,
                &self.clock,
                self.cfg.batch_aggregation_shard_count,
                req_bytes,
                collector_hpke_config,
            )
            .await
    }

    /// Opts in or out of a taskprov task.
    #[tracing::instrument(skip(self, aggregator_auth_token), err(level = Level::DEBUG))]
    async fn taskprov_opt_in(
        &self,
        peer_role: &Role,
        task_id: &TaskId,
        task_config: &TaskConfig,
        aggregator_auth_token: Option<&AuthenticationToken>,
    ) -> Result<(), Error> {
        let (peer_aggregator, leader_url, _) = self
            .taskprov_authorize_request(peer_role, task_id, task_config, aggregator_auth_token)
            .await?;

        // TODO(#1647): Check whether task config parameters are acceptable for privacy and
        // availability of the system.

        if let DpMechanism::Unrecognized { .. } =
            task_config.vdaf_config().dp_config().dp_mechanism()
        {
            if !self
                .cfg
                .taskprov_config
                .ignore_unknown_differential_privacy_mechanism
            {
                return Err(Error::InvalidTask(
                    *task_id,
                    OptOutReason::InvalidParameter("unrecognized DP mechanism".into()),
                ));
            }
        }

        let vdaf_instance =
            task_config
                .vdaf_config()
                .vdaf_type()
                .try_into()
                .map_err(|err: &str| {
                    Error::InvalidTask(*task_id, OptOutReason::InvalidParameter(err.to_string()))
                })?;

        let vdaf_verify_key = peer_aggregator.derive_vdaf_verify_key(task_id, &vdaf_instance);

        let task = Arc::new(
            AggregatorTask::new(
                *task_id,
                leader_url,
                task_config.query_config().query().try_into()?,
                vdaf_instance,
                vdaf_verify_key,
                task_config.query_config().max_batch_query_count() as u64,
                Some(*task_config.task_expiration()),
                peer_aggregator.report_expiry_age().cloned(),
                task_config.query_config().min_batch_size() as u64,
                *task_config.query_config().time_precision(),
                *peer_aggregator.tolerable_clock_skew(),
                // Taskprov task has no per-task HPKE keys
                [],
                task::AggregatorTaskParameters::TaskprovHelper,
            )
            .map_err(|err| Error::InvalidTask(*task_id, OptOutReason::TaskParameters(err)))?
            .with_taskprov_task_info(task_config.task_info().to_vec()),
        );
        self.datastore
            .run_tx("taskprov_put_task", |tx| {
                let task = Arc::clone(&task);
                Box::pin(async move { tx.put_aggregator_task(&task).await })
            })
            .await
            .or_else(|error| -> Result<(), Error> {
                match error {
                    // If the task is already in the datastore, then some other request or aggregator
                    // replica beat us to inserting it. They _should_ have inserted all the same parameters
                    // as we would have, so we can proceed as normal.
                    DatastoreError::MutationTargetAlreadyExists => {
                        warn!(
                            ?task_id,
                            ?error,
                            "taskprov: went to insert task into db, but it already exists"
                        );
                        Ok(())
                    }
                    error => Err(error.into()),
                }
            })?;

        info!(?task, ?peer_aggregator, "taskprov: opted into new task");
        Ok(())
    }

    /// Validate and authorize a taskprov request. Returns values necessary for determining whether
    /// we can opt into the task. This function might return an opt-out error for conditions that
    /// are relevant for all DAP workflows (e.g. task expiration).
    #[tracing::instrument(skip(self, aggregator_auth_token), err(level = Level::DEBUG))]
    async fn taskprov_authorize_request(
        &self,
        peer_role: &Role,
        task_id: &TaskId,
        task_config: &TaskConfig,
        aggregator_auth_token: Option<&AuthenticationToken>,
    ) -> Result<(&PeerAggregator, Url, Url), Error> {
        let peer_aggregator_url = match peer_role {
            Role::Leader => task_config.leader_aggregator_endpoint(),
            Role::Helper => task_config.helper_aggregator_endpoint(),
            _ => panic!("Unexpected role {peer_role}"),
        }
        .try_into()?;

        let peer_aggregator = self
            .peer_aggregators
            .get(&peer_aggregator_url, peer_role)
            .ok_or(Error::InvalidTask(
                *task_id,
                OptOutReason::NoSuchPeer(*peer_role),
            ))?;

        if !aggregator_auth_token
            .map(|t| peer_aggregator.check_aggregator_auth_token(t))
            .unwrap_or(false)
        {
            return Err(Error::UnauthorizedRequest(*task_id));
        }

        if self.clock.now() > *task_config.task_expiration() {
            return Err(Error::InvalidTask(*task_id, OptOutReason::TaskExpired));
        }

        debug!(
            ?task_id,
            ?task_config,
            ?peer_aggregator,
            "taskprov: authorized request"
        );
        Ok((
            peer_aggregator,
            task_config.leader_aggregator_endpoint().try_into()?,
            task_config.helper_aggregator_endpoint().try_into()?,
        ))
    }

    #[cfg(feature = "test-util")]
    pub async fn refresh_caches(&self) -> Result<(), Error> {
        self.global_hpke_keypairs.refresh(&self.datastore).await
    }
}

/// TaskAggregator provides aggregation functionality for a single task.
// TODO(#1307): refactor Aggregator to perform indepedent batched operations (e.g. report handling
// in Aggregate requests) using a parallelized library like Rayon.
#[derive(Debug)]
pub struct TaskAggregator<C: Clock> {
    /// The task being aggregated.
    pub(crate) task: Arc<AggregatorTask>,
    /// VDAF-specific operations.
    vdaf_ops: VdafOps,
    /// Report writer, with support for batching.
    report_writer: Arc<ReportWriteBatcher<C>>,
}

impl<C: Clock> TaskAggregator<C> {
    /// Create a new aggregator. `report_recipient` is used to decrypt reports received by this
    /// aggregator.
    pub fn new(
        task: AggregatorTask,
        report_writer: Arc<ReportWriteBatcher<C>>,
    ) -> Result<Self, Error> {
        let vdaf_ops = match task.vdaf() {
            VdafInstance::Prio3Count => {
                let vdaf = Prio3::new_count(2)?;
                let verify_key = task.vdaf_verify_key()?;
                VdafOps::Prio3Count(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3Sum { bits } => {
                let vdaf = Prio3::new_sum(2, *bits)?;
                let verify_key = task.vdaf_verify_key()?;
                VdafOps::Prio3Sum(Arc::new(vdaf), verify_key)
            }

            VdafInstance::Prio3SumVec {
                bits,
                length,
                chunk_length,
                dp_strategy,
            } => {
                let vdaf = Prio3::new_sum_vec(2, *bits, *length, *chunk_length)?;
                let verify_key = task.vdaf_verify_key()?;
                VdafOps::Prio3SumVec(
                    Arc::new(vdaf),
                    verify_key,
                    vdaf_ops_strategies::Prio3SumVec::from_vdaf_dp_strategy(dp_strategy.clone()),
                )
            }

            VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs,
                bits,
                length,
                chunk_length,
                dp_strategy,
            } => {
                let vdaf = new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128::<
                    ParallelSum<Field64, Mul<Field64>>,
                >(*proofs, *bits, *length, *chunk_length)?;
                let verify_key = task.vdaf_verify_key()?;
                VdafOps::Prio3SumVecField64MultiproofHmacSha256Aes128(
                    Arc::new(vdaf),
                    verify_key,
                    vdaf_ops_strategies::Prio3SumVec::from_vdaf_dp_strategy(dp_strategy.clone()),
                )
            }

            VdafInstance::Prio3Histogram {
                length,
                chunk_length,
                dp_strategy,
            } => {
                let vdaf = Prio3::new_histogram(2, *length, *chunk_length)?;
                let verify_key = task.vdaf_verify_key()?;
                VdafOps::Prio3Histogram(
                    Arc::new(vdaf),
                    verify_key,
                    vdaf_ops_strategies::Prio3Histogram::from_vdaf_dp_strategy(dp_strategy.clone()),
                )
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy,
                length,
            } => match bitsize {
                Prio3FixedPointBoundedL2VecSumBitSize::BitSize16 => {
                    let vdaf: Prio3FixedPointBoundedL2VecSum<FixedI16<U15>> =
                        Prio3::new_fixedpoint_boundedl2_vec_sum(2, *length)?;
                    let verify_key = task.vdaf_verify_key()?;
                    VdafOps::Prio3FixedPoint16BitBoundedL2VecSum(
                        Arc::new(vdaf),
                        verify_key,
                        vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum::from_vdaf_dp_strategy(
                            dp_strategy.clone(),
                        ),
                    )
                }
                Prio3FixedPointBoundedL2VecSumBitSize::BitSize32 => {
                    let vdaf: Prio3FixedPointBoundedL2VecSum<FixedI32<U31>> =
                        Prio3::new_fixedpoint_boundedl2_vec_sum(2, *length)?;
                    let verify_key = task.vdaf_verify_key()?;
                    VdafOps::Prio3FixedPoint32BitBoundedL2VecSum(
                        Arc::new(vdaf),
                        verify_key,
                        vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum::from_vdaf_dp_strategy(
                            dp_strategy.clone(),
                        ),
                    )
                }
            },

            VdafInstance::Poplar1 { bits } => {
                let vdaf = Poplar1::new_turboshake128(*bits);
                let verify_key = task.vdaf_verify_key()?;
                VdafOps::Poplar1(Arc::new(vdaf), verify_key)
            }

            #[cfg(feature = "test-util")]
            VdafInstance::Fake { rounds } => VdafOps::Fake(Arc::new(dummy::Vdaf::new(*rounds))),

            #[cfg(feature = "test-util")]
            VdafInstance::FakeFailsPrepInit => VdafOps::Fake(Arc::new(
                dummy::Vdaf::new(1).with_prep_init_fn(|_| -> Result<(), VdafError> {
                    Err(VdafError::Uncategorized(
                        "FakeFailsPrepInit failed at prep_init".to_string(),
                    ))
                }),
            )),

            #[cfg(feature = "test-util")]
            VdafInstance::FakeFailsPrepStep => {
                VdafOps::Fake(Arc::new(dummy::Vdaf::new(1).with_prep_step_fn(
                    |_| -> Result<PrepareTransition<dummy::Vdaf, 0, 16>, VdafError> {
                        Err(VdafError::Uncategorized(
                            "FakeFailsPrepStep failed at prep_step".to_string(),
                        ))
                    },
                )))
            }

            _ => panic!("VDAF {:?} is not yet supported", task.vdaf()),
        };

        Ok(Self {
            task: Arc::new(task),
            vdaf_ops,
            report_writer,
        })
    }

    fn handle_hpke_config(&self) -> Option<HpkeConfigList> {
        // TODO(#239): consider deciding a better way to determine "primary" (e.g. most-recent) HPKE
        // config/key -- right now it's the one with the maximal config ID, but that will run into
        // trouble if we ever need to wrap-around, which we may since config IDs are effectively a u8.
        Some(HpkeConfigList::new(Vec::from([self
            .task
            .hpke_keys()
            .iter()
            .max_by_key(|(&id, _)| id)?
            .1
            .config()
            .clone()])))
    }

    async fn handle_upload(
        &self,
        clock: &C,
        global_hpke_keypairs: &GlobalHpkeKeypairCache,
        metrics: &AggregatorMetrics,
        report: Report,
    ) -> Result<(), Arc<Error>> {
        self.vdaf_ops
            .handle_upload(
                clock,
                global_hpke_keypairs,
                metrics,
                &self.task,
                &self.report_writer,
                report,
            )
            .await
    }

    async fn handle_aggregate_init(
        &self,
        datastore: Arc<Datastore<C>>,
        clock: &C,
        global_hpke_keypairs: &GlobalHpkeKeypairCache,
        metrics: &AggregatorMetrics,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        require_taskprov_extension: bool,
        log_forbidden_mutations: Option<PathBuf>,
        req_bytes: &[u8],
    ) -> Result<AggregationJobResp, Error> {
        self.vdaf_ops
            .handle_aggregate_init(
                datastore,
                clock,
                global_hpke_keypairs,
                metrics,
                Arc::clone(&self.task),
                batch_aggregation_shard_count,
                task_counter_shard_count,
                aggregation_job_id,
                require_taskprov_extension,
                log_forbidden_mutations,
                req_bytes,
            )
            .await
    }

    async fn handle_aggregate_continue(
        &self,
        datastore: Arc<Datastore<C>>,
        metrics: &AggregatorMetrics,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req: AggregationJobContinueReq,
        request_hash: [u8; 32],
    ) -> Result<AggregationJobResp, Error> {
        self.vdaf_ops
            .handle_aggregate_continue(
                datastore,
                metrics,
                Arc::clone(&self.task),
                batch_aggregation_shard_count,
                task_counter_shard_count,
                aggregation_job_id,
                Arc::new(req),
                request_hash,
            )
            .await
    }

    async fn handle_aggregate_delete(
        &self,
        datastore: &Datastore<C>,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_aggregate_delete(datastore, Arc::clone(&self.task), aggregation_job_id)
            .await
    }

    async fn handle_create_collection_job(
        &self,
        datastore: &Datastore<C>,
        collection_job_id: &CollectionJobId,
        req_bytes: &[u8],
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_create_collection_job(
                datastore,
                Arc::clone(&self.task),
                collection_job_id,
                req_bytes,
            )
            .await
    }

    async fn handle_get_collection_job(
        &self,
        datastore: &Datastore<C>,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.vdaf_ops
            .handle_get_collection_job(datastore, Arc::clone(&self.task), collection_job_id)
            .await
    }

    async fn handle_delete_collection_job(
        &self,
        datastore: &Datastore<C>,
        collection_job_id: &CollectionJobId,
    ) -> Result<(), Error> {
        self.vdaf_ops
            .handle_delete_collection_job(datastore, Arc::clone(&self.task), collection_job_id)
            .await
    }

    async fn handle_aggregate_share(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        batch_aggregation_shard_count: u64,
        req_bytes: &[u8],
        collector_hpke_config: &HpkeConfig,
    ) -> Result<AggregateShare, Error> {
        self.vdaf_ops
            .handle_aggregate_share(
                datastore,
                clock,
                Arc::clone(&self.task),
                batch_aggregation_shard_count,
                req_bytes,
                collector_hpke_config,
            )
            .await
    }
}

mod vdaf_ops_strategies {
    use std::sync::Arc;

    use janus_core::vdaf::vdaf_dp_strategies;
    use prio::dp::distributions::PureDpDiscreteLaplace;
    #[cfg(feature = "fpvec_bounded_l2")]
    use prio::dp::distributions::ZCdpDiscreteGaussian;

    #[derive(Debug)]
    pub enum Prio3Histogram {
        NoDifferentialPrivacy,
        PureDpDiscreteLaplace(Arc<PureDpDiscreteLaplace>),
    }

    impl Prio3Histogram {
        pub fn from_vdaf_dp_strategy(dp_strategy: vdaf_dp_strategies::Prio3Histogram) -> Self {
            match dp_strategy {
                vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy => {
                    Prio3Histogram::NoDifferentialPrivacy
                }
                vdaf_dp_strategies::Prio3Histogram::PureDpDiscreteLaplace(s) => {
                    Prio3Histogram::PureDpDiscreteLaplace(Arc::new(s))
                }
            }
        }
    }

    #[derive(Debug)]
    pub enum Prio3SumVec {
        NoDifferentialPrivacy,
        PureDpDiscreteLaplace(Arc<PureDpDiscreteLaplace>),
    }

    impl Prio3SumVec {
        pub fn from_vdaf_dp_strategy(dp_strategy: vdaf_dp_strategies::Prio3SumVec) -> Self {
            match dp_strategy {
                vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy => {
                    Prio3SumVec::NoDifferentialPrivacy
                }
                vdaf_dp_strategies::Prio3SumVec::PureDpDiscreteLaplace(s) => {
                    Prio3SumVec::PureDpDiscreteLaplace(Arc::new(s))
                }
            }
        }
    }

    #[cfg(feature = "fpvec_bounded_l2")]
    #[derive(Debug)]
    pub enum Prio3FixedPointBoundedL2VecSum {
        NoDifferentialPrivacy,
        ZCdpDiscreteGaussian(Arc<ZCdpDiscreteGaussian>),
    }

    #[cfg(feature = "fpvec_bounded_l2")]
    impl Prio3FixedPointBoundedL2VecSum {
        pub fn from_vdaf_dp_strategy(
            dp_strategy: vdaf_dp_strategies::Prio3FixedPointBoundedL2VecSum,
        ) -> Self {
            match dp_strategy {
                vdaf_dp_strategies::Prio3FixedPointBoundedL2VecSum::NoDifferentialPrivacy => {
                    Prio3FixedPointBoundedL2VecSum::NoDifferentialPrivacy
                }
                vdaf_dp_strategies::Prio3FixedPointBoundedL2VecSum::ZCdpDiscreteGaussian(s) => {
                    Prio3FixedPointBoundedL2VecSum::ZCdpDiscreteGaussian(Arc::new(s))
                }
            }
        }
    }
}

/// VdafOps stores VDAF-specific operations for a TaskAggregator in a non-generic way.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum VdafOps {
    Prio3Count(Arc<Prio3Count>, VerifyKey<VERIFY_KEY_LENGTH>),
    Prio3Sum(Arc<Prio3Sum>, VerifyKey<VERIFY_KEY_LENGTH>),
    Prio3SumVec(
        Arc<Prio3SumVec>,
        VerifyKey<VERIFY_KEY_LENGTH>,
        vdaf_ops_strategies::Prio3SumVec,
    ),
    Prio3SumVecField64MultiproofHmacSha256Aes128(
        Arc<Prio3SumVecField64MultiproofHmacSha256Aes128<ParallelSum<Field64, Mul<Field64>>>>,
        VerifyKey<32>,
        vdaf_ops_strategies::Prio3SumVec,
    ),
    Prio3Histogram(
        Arc<Prio3Histogram>,
        VerifyKey<VERIFY_KEY_LENGTH>,
        vdaf_ops_strategies::Prio3Histogram,
    ),
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint16BitBoundedL2VecSum(
        Arc<Prio3FixedPointBoundedL2VecSum<FixedI16<U15>>>,
        VerifyKey<VERIFY_KEY_LENGTH>,
        vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum,
    ),
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPoint32BitBoundedL2VecSum(
        Arc<Prio3FixedPointBoundedL2VecSum<FixedI32<U31>>>,
        VerifyKey<VERIFY_KEY_LENGTH>,
        vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum,
    ),
    Poplar1(
        Arc<Poplar1<XofTurboShake128, 16>>,
        VerifyKey<VERIFY_KEY_LENGTH>,
    ),
    #[cfg(feature = "test-util")]
    Fake(Arc<dummy::Vdaf>),
}

/// Emits a match block dispatching on a [`VdafOps`] object. Takes a `&VdafOps` as the first
/// argument, followed by a pseudo-pattern and body. The pseudo-pattern takes variable names for the
/// constructed VDAF and the verify key, a type alias name that the block can use to explicitly
/// specify the VDAF's type, and the name of a const that will be set to the VDAF's verify key
/// length, also for explicitly specifying type parameters.
macro_rules! vdaf_ops_dispatch {
    ($vdaf_ops:expr, ($vdaf:pat_param, $verify_key:pat_param, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident, $dp_strategy:ident, $DpStrategy:ident) => $body:tt) => {
        match $vdaf_ops {
            crate::aggregator::VdafOps::Prio3Count(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Count;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;
                type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                let body = $body;
                body
            }

            crate::aggregator::VdafOps::Prio3Sum(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Sum;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;
                type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                let body = $body;
                body
            }

            crate::aggregator::VdafOps::Prio3SumVec(vdaf, verify_key, _dp_strategy) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3SumVec;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;
                match _dp_strategy {
                    vdaf_ops_strategies::Prio3SumVec::NoDifferentialPrivacy => {
                        type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                        let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                        let body = $body;
                        body
                    }
                    vdaf_ops_strategies::Prio3SumVec::PureDpDiscreteLaplace(_strategy) => {
                        type $DpStrategy = ::prio::dp::distributions::PureDpDiscreteLaplace;
                        let $dp_strategy = &_strategy;
                        let body = $body;
                        body
                    }
                }
            }

            crate::aggregator::VdafOps::Prio3SumVecField64MultiproofHmacSha256Aes128(vdaf, verify_key, _dp_strategy) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::janus_core::vdaf::Prio3SumVecField64MultiproofHmacSha256Aes128<
                    ::prio::flp::gadgets::ParallelSum<
                        ::prio::field::Field64,
                        ::prio::flp::gadgets::Mul<::prio::field::Field64>
                    >,
                >;
                const $VERIFY_KEY_LENGTH: usize = 32;
                match _dp_strategy {
                    vdaf_ops_strategies::Prio3SumVec::NoDifferentialPrivacy => {
                        type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                        let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                        let body = $body;
                        body
                    }
                    vdaf_ops_strategies::Prio3SumVec::PureDpDiscreteLaplace(_strategy) => {
                        type $DpStrategy = ::prio::dp::distributions::PureDpDiscreteLaplace;
                        let $dp_strategy = &_strategy;
                        let body = $body;
                        body
                    }
                }
            }

            crate::aggregator::VdafOps::Prio3Histogram(vdaf, verify_key, _dp_strategy) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3Histogram;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;
                match _dp_strategy {
                    vdaf_ops_strategies::Prio3Histogram::NoDifferentialPrivacy => {
                        type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                        let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                        let body = $body;
                        body
                    }
                    vdaf_ops_strategies::Prio3Histogram::PureDpDiscreteLaplace(_strategy) => {
                        type $DpStrategy = ::prio::dp::distributions::PureDpDiscreteLaplace;
                        let $dp_strategy = &_strategy;
                        let body = $body;
                        body
                    }
                }
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            // Note that the variable `_dp_strategy` is used if `$dp_strategy`
            // and `$DpStrategy` are given. The underscore suppresses warnings
            // which occur when `vdaf_ops!` is called without these parameters.
            crate::aggregator::VdafOps::Prio3FixedPoint16BitBoundedL2VecSum(vdaf, verify_key, _dp_strategy) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSum<FixedI16<U15>>;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;

                match _dp_strategy {
                    vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum::ZCdpDiscreteGaussian(_strategy) => {
                        type $DpStrategy = ::prio::dp::distributions::ZCdpDiscreteGaussian;
                        let $dp_strategy = &_strategy;
                        let body = $body;
                        body
                    },
                    vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum::NoDifferentialPrivacy => {
                        type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                        let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                        let body = $body;
                        body
                    }
                }
            }

            #[cfg(feature = "fpvec_bounded_l2")]
            // Note that the variable `_dp_strategy` is used if `$dp_strategy`
            // and `$DpStrategy` are given. The underscore suppresses warnings
            // which occur when `vdaf_ops!` is called without these parameters.
            crate::aggregator::VdafOps::Prio3FixedPoint32BitBoundedL2VecSum(vdaf, verify_key, _dp_strategy) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSum<FixedI32<U31>>;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;

                match _dp_strategy {
                    vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum::ZCdpDiscreteGaussian(_strategy) => {
                        type $DpStrategy = ::prio::dp::distributions::ZCdpDiscreteGaussian;
                        let $dp_strategy = &_strategy;
                        let body = $body;
                        body
                    },
                    vdaf_ops_strategies::Prio3FixedPointBoundedL2VecSum::NoDifferentialPrivacy => {
                        type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                        let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                        let body = $body;
                        body
                    }
                }
            }

            crate::aggregator::VdafOps::Poplar1(vdaf, verify_key) => {
                let $vdaf = vdaf;
                let $verify_key = verify_key;
                type $Vdaf = ::prio::vdaf::poplar1::Poplar1<::prio::vdaf::xof::XofTurboShake128, 16>;
                const $VERIFY_KEY_LENGTH: usize = ::janus_core::vdaf::VERIFY_KEY_LENGTH;
                type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                let body = $body;
                body
            }

            #[cfg(feature = "test-util")]
            crate::aggregator::VdafOps::Fake(vdaf) => {
                let $vdaf = vdaf;
                let $verify_key = &VerifyKey::new([]);
                type $Vdaf = ::prio::vdaf::dummy::Vdaf;
                const $VERIFY_KEY_LENGTH: usize = 0;
                type $DpStrategy = janus_core::dp::NoDifferentialPrivacy;
                let $dp_strategy = &Arc::new(janus_core::dp::NoDifferentialPrivacy);
                let body = $body;
                body
            }
        }
    };

    ($vdaf_ops:expr, ($vdaf:pat_param, $verify_key:pat_param, $Vdaf:ident, $VERIFY_KEY_LENGTH:ident) => $body:tt) => {
        vdaf_ops_dispatch!($vdaf_ops, ($vdaf, $verify_key, $Vdaf, $VERIFY_KEY_LENGTH, _unused, _Unused) => $body)};
}

impl VdafOps {
    #[tracing::instrument(skip_all, fields(task_id = ?task.id()), err(level = Level::DEBUG))]
    async fn handle_upload<C: Clock>(
        &self,
        clock: &C,
        global_hpke_keypairs: &GlobalHpkeKeypairCache,
        metrics: &AggregatorMetrics,
        task: &AggregatorTask,
        report_writer: &ReportWriteBatcher<C>,
        report: Report,
    ) -> Result<(), Arc<Error>> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_upload_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        Arc::clone(vdaf),
                        clock,
                        global_hpke_keypairs,
                        metrics,
                        task,
                        report_writer,
                        report,
                    )
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_upload_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        Arc::clone(vdaf),
                        clock,
                        global_hpke_keypairs,
                        metrics,
                        task,
                        report_writer,
                        report,
                    )
                    .await
                })
            }
        }
    }

    /// Implements [helper aggregate initialization][1].
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-helper-initialization
    #[tracing::instrument(
        skip(self, datastore, global_hpke_keypairs, metrics, task, req_bytes),
        fields(task_id = ?task.id()),
        err(level = Level::DEBUG)
    )]
    async fn handle_aggregate_init<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        clock: &C,
        global_hpke_keypairs: &GlobalHpkeKeypairCache,
        metrics: &AggregatorMetrics,
        task: Arc<AggregatorTask>,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        require_taskprov_extension: bool,
        log_forbidden_mutations: Option<PathBuf>,
        req_bytes: &[u8],
    ) -> Result<AggregationJobResp, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, verify_key, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_init_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        datastore,
                        clock,
                        global_hpke_keypairs,
                        Arc::clone(vdaf),
                        metrics,
                        task,
                        batch_aggregation_shard_count,
                        task_counter_shard_count,
                        aggregation_job_id,
                        verify_key,
                        require_taskprov_extension,
                        log_forbidden_mutations,
                        req_bytes,
                    )
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, verify_key, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_init_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        datastore,
                        clock,
                        global_hpke_keypairs,
                        Arc::clone(vdaf),
                        metrics,
                        task,
                        batch_aggregation_shard_count,
                        task_counter_shard_count,
                        aggregation_job_id,
                        verify_key,
                        require_taskprov_extension,
                        log_forbidden_mutations,
                        req_bytes,
                    )
                    .await
                })
            }
        }
    }

    #[tracing::instrument(
        skip(self, datastore, metrics, task, req, request_hash),
        fields(task_id = ?task.id()),
        err(level = Level::DEBUG)
    )]
    async fn handle_aggregate_continue<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        metrics: &AggregatorMetrics,
        task: Arc<AggregatorTask>,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req: Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
    ) -> Result<AggregationJobResp, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_continue_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        datastore,
                        Arc::clone(vdaf),
                        metrics,
                        task,
                        batch_aggregation_shard_count,
                        task_counter_shard_count,
                        aggregation_job_id,
                        req,
                        request_hash,
                    )
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_continue_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        datastore,
                        Arc::clone(vdaf),
                        metrics,
                        task,
                        batch_aggregation_shard_count,
                        task_counter_shard_count,
                        aggregation_job_id,
                        req,
                        request_hash,
                    )
                    .await
                })
            }
        }
    }

    #[tracing::instrument(skip(self, datastore), fields(task_id = ?task.id()), err(level = Level::DEBUG))]
    async fn handle_aggregate_delete<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<(), Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (_, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_delete_generic::<VERIFY_KEY_LENGTH, TimeInterval, VdafType, _>(
                        datastore,
                        task,
                        aggregation_job_id,
                    ).await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (_, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_aggregate_delete_generic::<VERIFY_KEY_LENGTH, FixedSize, VdafType, _>(
                        datastore,
                        task,
                        aggregation_job_id,
                    ).await
                })
            }
        }
    }

    async fn handle_upload_generic<const SEED_SIZE: usize, Q, A, C>(
        vdaf: Arc<A>,
        clock: &C,
        global_hpke_keypairs: &GlobalHpkeKeypairCache,
        metrics: &AggregatorMetrics,
        task: &AggregatorTask,
        report_writer: &ReportWriteBatcher<C>,
        report: Report,
    ) -> Result<(), Arc<Error>>
    where
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        A::InputShare: PartialEq + Send + Sync,
        A::PublicShare: PartialEq + Send + Sync,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        C: Clock,
        Q: UploadableQueryType,
    {
        // Shorthand function for generating an Error::ReportRejected with proper parameters and
        // recording it in the report_writer.
        let reject_report = |reason| {
            let report_id = *report.metadata().id();
            let report_time = *report.metadata().time();
            async move {
                let rejection = ReportRejection::new(*task.id(), report_id, report_time, reason);
                report_writer.write_rejection(rejection).await;
                Ok::<_, Arc<Error>>(Arc::new(Error::ReportRejected(rejection)))
            }
        };

        let report_deadline = clock
            .now()
            .add(task.tolerable_clock_skew())
            .map_err(|err| Arc::new(Error::from(err)))?;

        // Reject reports from too far in the future.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#section-4.4.2-21
        if report.metadata().time().is_after(&report_deadline) {
            return Err(reject_report(ReportRejectionReason::TooEarly).await?);
        }

        // Reject reports after a task has expired.
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#section-4.4.2-20
        if let Some(task_expiration) = task.task_expiration() {
            if report.metadata().time().is_after(task_expiration) {
                return Err(reject_report(ReportRejectionReason::TaskExpired).await?);
            }
        }

        // Reject reports that would be eligible for garbage collection, to prevent replay attacks.
        if let Some(report_expiry_age) = task.report_expiry_age() {
            let report_expiry_time = report
                .metadata()
                .time()
                .add(report_expiry_age)
                .map_err(|err| Arc::new(Error::from(err)))?;
            if clock.now().is_after(&report_expiry_time) {
                return Err(reject_report(ReportRejectionReason::Expired).await?);
            }
        }

        // Decode (and in the case of the leader input share, decrypt) the remaining fields of the
        // report before storing them in the datastore. The spec does not require the
        // `tasks/{task-id}/reports` handler to do this, but it exercises HPKE decryption, saves us
        // the trouble of storing reports we can't use, and lets the aggregation job handler assume
        // the values it reads from the datastore are valid.
        let public_share =
            match A::PublicShare::get_decoded_with_param(vdaf.as_ref(), report.public_share()) {
                Ok(public_share) => public_share,
                Err(err) => {
                    debug!(
                        report.task_id = %task.id(),
                        report.metadata = ?report.metadata(),
                        ?err,
                        "public share decoding failed",
                    );
                    metrics.upload_decode_failure_counter.add(1, &[]);
                    return Err(reject_report(ReportRejectionReason::DecodeFailure).await?);
                }
            };

        let input_share_aad = InputShareAad::new(
            *task.id(),
            report.metadata().clone(),
            report.public_share().to_vec(),
        )
        .get_encoded()
        .map_err(|e| Arc::new(Error::MessageEncode(e)))?;
        let try_hpke_open = |hpke_keypair: &HpkeKeypair| {
            hpke::open(
                hpke_keypair,
                &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, task.role()),
                report.leader_encrypted_input_share(),
                &input_share_aad,
            )
        };

        let global_hpke_keypair =
            global_hpke_keypairs.keypair(report.leader_encrypted_input_share().config_id());

        let task_hpke_keypair = task
            .hpke_keys()
            .get(report.leader_encrypted_input_share().config_id());

        let decryption_result = match (task_hpke_keypair, global_hpke_keypair) {
            // Verify that the report's HPKE config ID is known.
            // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#section-4.4.2-17
            (None, None) => {
                return Err(reject_report(ReportRejectionReason::OutdatedHpkeConfig(
                    *report.leader_encrypted_input_share().config_id(),
                ))
                .await?);
            }
            (None, Some(global_hpke_keypair)) => try_hpke_open(&global_hpke_keypair),
            (Some(task_hpke_keypair), None) => try_hpke_open(task_hpke_keypair),
            (Some(task_hpke_keypair), Some(global_hpke_keypair)) => {
                try_hpke_open(task_hpke_keypair).or_else(|error| match error {
                    // Only attempt second trial if _decryption_ fails, and not some
                    // error in server-side HPKE configuration.
                    hpke::Error::Hpke(_) => try_hpke_open(&global_hpke_keypair),
                    error => Err(error),
                })
            }
        };

        let encoded_leader_input_share = match decryption_result {
            Ok(plaintext) => plaintext,
            Err(error) => {
                debug!(
                    report.task_id = %task.id(),
                    report.metadata = ?report.metadata(),
                    ?error,
                    "Report decryption failed",
                );
                metrics.upload_decrypt_failure_counter.add(1, &[]);
                return Err(reject_report(ReportRejectionReason::DecryptFailure).await?);
            }
        };

        let decoded_leader_input_share = PlaintextInputShare::get_decoded(
            &encoded_leader_input_share,
        )
        .and_then(|plaintext_input_share| {
            Ok((
                plaintext_input_share.extensions().to_vec(),
                A::InputShare::get_decoded_with_param(
                    &(&vdaf, Role::Leader.index().unwrap()),
                    plaintext_input_share.payload(),
                )?,
            ))
        });

        let (extensions, leader_input_share) = match decoded_leader_input_share {
            Ok(leader_input_share) => leader_input_share,
            Err(err) => {
                debug!(
                    report.task_id = %task.id(),
                    report.metadata = ?report.metadata(),
                    ?err,
                    "Leader input share decoding failed",
                );
                metrics.upload_decode_failure_counter.add(1, &[]);
                return Err(reject_report(ReportRejectionReason::DecodeFailure).await?);
            }
        };

        let report = LeaderStoredReport::new(
            *task.id(),
            report.metadata().clone(),
            public_share,
            extensions,
            leader_input_share,
            report.helper_encrypted_input_share().clone(),
        );

        report_writer
            .write_report(Box::new(WritableReport::<SEED_SIZE, Q, A>::new(
                vdaf, report,
            )))
            .await
    }
}

/// Used by the aggregation job initialization handler to represent initialization of a report
/// share.
#[derive(Clone)]
struct ReportShareData<const SEED_SIZE: usize, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16>,
{
    report_share: ReportShare,
    report_aggregation: WritableReportAggregation<SEED_SIZE, A>,
}

impl VdafOps {
    async fn check_aggregate_init_idempotency<const SEED_SIZE: usize, Q, A, C>(
        tx: &Transaction<'_, C>,
        vdaf: &A,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
        req: &AggregationJobInitializeReq<Q>,
        request_hash: [u8; 32],
        log_forbidden_mutations: Option<PathBuf>,
    ) -> Result<Option<AggregationJobResp>, datastore::Error>
    where
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
        C: Clock,
        for<'a> A::PrepareState: ParameterizedDecode<(&'a A, usize)>,
    {
        if let Some(existing_aggregation_job) = tx
            .get_aggregation_job::<SEED_SIZE, Q, A>(task_id, aggregation_job_id)
            .await?
        {
            if existing_aggregation_job.state() == &AggregationJobState::Deleted {
                return Err(datastore::Error::User(
                    Error::DeletedAggregationJob(*task_id, *aggregation_job_id).into(),
                ));
            }

            if existing_aggregation_job.last_request_hash() != Some(request_hash) {
                if let Some(log_forbidden_mutations) = log_forbidden_mutations {
                    let original_report_metadatas: Vec<_> = tx
                        .get_report_aggregations_for_aggregation_job(
                            vdaf,
                            &Role::Helper,
                            task_id,
                            aggregation_job_id,
                        )
                        .await?
                        .iter()
                        .map(|ra| ra.report_metadata())
                        .collect();
                    let mutating_request_report_metadatas: Vec<_> = req
                        .prepare_inits()
                        .iter()
                        .map(|pi| pi.report_share().metadata().clone())
                        .collect();
                    let event = AggregationJobInitForbiddenMutationEvent {
                        task_id: *task_id,
                        aggregation_job_id: *aggregation_job_id,
                        original_request_hash: existing_aggregation_job.last_request_hash(),
                        original_report_metadatas,
                        original_batch_id: format!(
                            "{:?}",
                            existing_aggregation_job.partial_batch_identifier()
                        ),
                        original_aggregation_parameter: existing_aggregation_job
                            .aggregation_parameter()
                            .get_encoded()
                            .map_err(|e| datastore::Error::User(e.into()))?,
                        mutating_request_hash: Some(request_hash),
                        mutating_request_report_metadatas,
                        mutating_request_batch_id: format!(
                            "{:?}",
                            req.batch_selector().batch_identifier()
                        ),
                        mutating_request_aggregation_parameter: req
                            .aggregation_parameter()
                            .to_vec(),
                    };
                    let event_id = crate::diagnostic::write_event(
                        log_forbidden_mutations,
                        "agg-job-illegal-mutation",
                        event,
                    )
                    .await
                    .map(|event_id| format!("{event_id:?}"))
                    .unwrap_or_else(|error| {
                        tracing::error!(?error, "failed to write hash mismatch event");
                        "no event id".to_string()
                    });

                    tracing::info!(
                        ?event_id,
                        original_request_hash = existing_aggregation_job
                            .last_request_hash()
                            .map(hex::encode),
                        mutating_request_hash = hex::encode(request_hash),
                        "request hash mismatch on retried aggregation job request",
                    );
                }
                return Err(datastore::Error::User(
                    Error::ForbiddenMutation {
                        resource_type: "aggregation job",
                        identifier: aggregation_job_id.to_string(),
                    }
                    .into(),
                ));
            }

            // This is a repeated request. Send the same response we computed last time.
            return Ok(Some(AggregationJobResp::new(
                tx.get_report_aggregations_for_aggregation_job(
                    vdaf,
                    &Role::Helper,
                    task_id,
                    aggregation_job_id,
                )
                .await?
                .iter()
                .filter_map(ReportAggregation::last_prep_resp)
                .cloned()
                .collect(),
            )));
        }

        Ok(None)
    }

    /// Implements [helper aggregate initialization][1].
    ///
    /// [1]: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-helper-initialization
    async fn handle_aggregate_init_generic<const SEED_SIZE: usize, Q, A, C>(
        datastore: Arc<Datastore<C>>,
        clock: &C,
        global_hpke_keypairs: &GlobalHpkeKeypairCache,
        vdaf: Arc<A>,
        metrics: &AggregatorMetrics,
        task: Arc<AggregatorTask>,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        verify_key: &VerifyKey<SEED_SIZE>,
        require_taskprov_extension: bool,
        log_forbidden_mutations: Option<PathBuf>,
        req_bytes: &[u8],
    ) -> Result<AggregationJobResp, Error>
    where
        Q: AccumulableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + 'static + Send + Sync,
        C: Clock,
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::AggregateShare: Send + Sync,
        A::InputShare: Send + Sync,
        A::PrepareMessage: Send + Sync + PartialEq,
        A::PrepareShare: Send + Sync + PartialEq,
        for<'a> A::PrepareState:
            Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)> + PartialEq,
        A::PublicShare: Send + Sync,
        A::OutputShare: Send + Sync + PartialEq,
    {
        // unwrap safety: SHA-256 computed by ring should always be 32 bytes
        let request_hash = digest(&SHA256, req_bytes).as_ref().try_into().unwrap();
        let req = Arc::new(
            AggregationJobInitializeReq::<Q>::get_decoded(req_bytes)
                .map_err(Error::MessageDecode)?,
        );

        // Check if this is a repeated request, and if it is the same as before, send
        // the same response as last time.
        if let Some(response) = datastore
            .run_tx("aggregate_init_idempotecy_check", |tx| {
                let vdaf = vdaf.clone();
                let task = Arc::clone(&task);
                let aggregation_job_id = *aggregation_job_id;
                let req = Arc::clone(&req);
                let log_forbidden_mutations = log_forbidden_mutations.clone();

                Box::pin(async move {
                    Self::check_aggregate_init_idempotency(
                        tx,
                        vdaf.as_ref(),
                        task.id(),
                        &aggregation_job_id,
                        &req,
                        request_hash,
                        log_forbidden_mutations,
                    )
                    .await
                })
            })
            .await?
        {
            return Ok(response);
        }

        let agg_param = Arc::new(
            A::AggregationParam::get_decoded(req.aggregation_parameter())
                .map_err(Error::MessageDecode)?,
        );

        let report_deadline = clock
            .now()
            .add(task.tolerable_clock_skew())
            .map_err(Error::from)?;

        // If two ReportShare messages have the same report ID, then the helper MUST abort with
        // error "invalidMessage". (§4.5.1.2)
        let mut seen_report_ids = HashSet::with_capacity(req.prepare_inits().len());
        for prepare_init in req.prepare_inits() {
            if !seen_report_ids.insert(*prepare_init.report_share().metadata().id()) {
                return Err(Error::InvalidMessage(
                    Some(*task.id()),
                    "aggregate request contains duplicate report IDs",
                ));
            }
        }

        // Compute the next aggregation step.
        //
        // We validate that each prepare_init can be represented by a `u64` ord value here, so that
        // inside the parallel iterator we can unwrap. A conversion failure here will fail the
        // entire aggregation. However, this is desirable: this can only happen if we receive too
        // many report shares in an aggregation job for us to store, which is a whole-aggregation
        // problem rather than a per-report problem. (separately, this would require more than
        // u64::MAX report shares in a single aggregation job, which is practically impossible.)
        u64::try_from(req.prepare_inits().len())?;

        // Shutdown on cancellation: if this request is cancelled, the `receiver` will be dropped.
        // This will cause any attempts to send on `sender` to return a `SendError`, which will be
        // returned from the function passed to `try_for_each_with`; `try_for_each_with` will
        // terminate early on receiving an error.
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let producer_task = tokio::task::spawn_blocking({
            let parent_span = Span::current();
            let global_hpke_keypairs = global_hpke_keypairs.view();
            let vdaf = Arc::clone(&vdaf);
            let task = Arc::clone(&task);
            let metrics = metrics.clone();
            let req = Arc::clone(&req);
            let aggregation_job_id = *aggregation_job_id;
            let verify_key = *verify_key;
            let agg_param = Arc::clone(&agg_param);

            move || {
                let span = info_span!(parent: parent_span, "handle_aggregate_init_generic threadpool task");

                req
                    .prepare_inits()
                    .par_iter()
                    .enumerate()
                    .try_for_each_with((sender, span), |(sender, span), (ord, prepare_init)| {
                        let _entered = span.enter();

                        // If decryption fails, then the aggregator MUST fail with error `hpke-decrypt-error`. (§4.4.2.2)
                        let global_hpke_keypair = global_hpke_keypairs.keypair(
                            prepare_init
                                .report_share()
                                .encrypted_input_share()
                                .config_id(),
                        );

                        let task_hpke_keypair = task.hpke_keys().get(
                            prepare_init
                                .report_share()
                                .encrypted_input_share()
                                .config_id(),
                        );

                        let check_keypairs = if task_hpke_keypair.is_none()
                            && global_hpke_keypair.is_none()
                        {
                            debug!(
                                config_id = %prepare_init.report_share().encrypted_input_share().config_id(),
                                "Helper encrypted input share references unknown HPKE config ID"
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", "unknown_hpke_config_id")]);
                            Err(PrepareError::HpkeUnknownConfigId)
                        } else {
                            Ok(())
                        };

                        let input_share_aad = check_keypairs.and_then(|_| {
                            InputShareAad::new(
                                *task.id(),
                                prepare_init.report_share().metadata().clone(),
                                prepare_init.report_share().public_share().to_vec(),
                            )
                            .get_encoded()
                            .map_err(|err| {
                                debug!(
                                    task_id = %task.id(),
                                    metadata = ?prepare_init.report_share().metadata(),
                                    ?err,
                                    "Couldn't encode input share AAD"
                                );
                                metrics.aggregate_step_failure_counter.add(
                                    1,
                                    &[KeyValue::new("type", "input_share_aad_encode_failure")],
                                );
                                // HpkeDecryptError isn't strictly accurate, but given that this
                                // fallible encoding is part of the HPKE decryption process, I think
                                // this is as close as we can get to a meaningful error signal.
                                PrepareError::HpkeDecryptError
                            })
                        });

                        let plaintext = input_share_aad.and_then(|input_share_aad| {
                            let try_hpke_open = |hpke_keypair| {
                                hpke::open(
                                    hpke_keypair,
                                    &HpkeApplicationInfo::new(
                                        &Label::InputShare,
                                        &Role::Client,
                                        &Role::Helper,
                                    ),
                                    prepare_init.report_share().encrypted_input_share(),
                                    &input_share_aad,
                                )
                            };

                            match (task_hpke_keypair, global_hpke_keypair) {
                                (None, None) => unreachable!("already checked this condition"),
                                (None, Some(global_hpke_keypair)) => {
                                    try_hpke_open(&global_hpke_keypair)
                                }
                                (Some(task_hpke_keypair), None) => try_hpke_open(task_hpke_keypair),
                                (Some(task_hpke_keypair), Some(global_hpke_keypair)) => {
                                    try_hpke_open(task_hpke_keypair).or_else(|error| match error {
                                        // Only attempt second trial if _decryption_ fails, and not some
                                        // error in server-side HPKE configuration.
                                        hpke::Error::Hpke(_) => try_hpke_open(&global_hpke_keypair),
                                        error => Err(error),
                                    })
                                }
                            }
                            .map_err(|error| {
                                debug!(
                                    task_id = %task.id(),
                                    metadata = ?prepare_init.report_share().metadata(),
                                    ?error,
                                    "Couldn't decrypt helper's report share"
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "decrypt_failure")]);
                                PrepareError::HpkeDecryptError
                            })
                        });

                        let plaintext_input_share = plaintext.and_then(|plaintext| {
                            let plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext)
                                .map_err(|error| {
                                    debug!(
                                        task_id = %task.id(),
                                        metadata = ?prepare_init.report_share().metadata(),
                                        ?error, "Couldn't decode helper's plaintext input share",
                                    );
                                    metrics.aggregate_step_failure_counter.add(
                                        1,
                                        &[KeyValue::new(
                                            "type",
                                            "plaintext_input_share_decode_failure",
                                        )],
                                    );
                                    PrepareError::InvalidMessage
                                })?;

                            // Build map of extension type to extension data, checking for duplicates.
                            let mut extensions = HashMap::new();
                            if !plaintext_input_share.extensions().iter().all(|extension| {
                                extensions
                                    .insert(*extension.extension_type(), extension.extension_data())
                                    .is_none()
                            }) {
                                debug!(
                                    task_id = %task.id(),
                                    metadata = ?prepare_init.report_share().metadata(),
                                    "Received report share with duplicate extensions",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "duplicate_extension")]);
                                return Err(PrepareError::InvalidMessage);
                            }

                            if require_taskprov_extension {
                                let valid_taskprov_extension_present = extensions
                                    .get(&ExtensionType::Taskprov)
                                    .map(|data| data.is_empty())
                                    .unwrap_or(false);
                                if !valid_taskprov_extension_present {
                                    debug!(
                                        task_id = %task.id(),
                                        metadata = ?prepare_init.report_share().metadata(),
                                        "Taskprov task received report with missing or malformed \
                                        taskprov extension",
                                    );
                                    metrics.aggregate_step_failure_counter.add(
                                        1,
                                        &[KeyValue::new(
                                            "type",
                                            "missing_or_malformed_taskprov_extension",
                                        )],
                                    );
                                    return Err(PrepareError::InvalidMessage);
                                }
                            } else if extensions.contains_key(&ExtensionType::Taskprov) {
                                // taskprov not enabled, but the taskprov extension is present.
                                debug!(
                                    task_id = %task.id(),
                                    metadata = ?prepare_init.report_share().metadata(),
                                    "Non-taskprov task received report with unexpected taskprov \
                                    extension",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "unexpected_taskprov_extension")]);
                                return Err(PrepareError::InvalidMessage);
                            }

                            Ok(plaintext_input_share)
                        });

                        let input_share = plaintext_input_share.and_then(|plaintext_input_share| {
                            A::InputShare::get_decoded_with_param(
                                &(&vdaf, Role::Helper.index().unwrap()),
                                plaintext_input_share.payload(),
                            )
                            .map_err(|error| {
                                debug!(
                                    task_id = %task.id(),
                                    metadata = ?prepare_init.report_share().metadata(),
                                    ?error, "Couldn't decode helper's input share",
                                );
                                metrics
                                    .aggregate_step_failure_counter
                                    .add(1, &[KeyValue::new("type", "input_share_decode_failure")]);
                                PrepareError::InvalidMessage
                            })
                        });

                        let public_share = A::PublicShare::get_decoded_with_param(
                            &vdaf,
                            prepare_init.report_share().public_share(),
                        )
                        .map_err(|error| {
                            debug!(
                                task_id = %task.id(),
                                metadata = ?prepare_init.report_share().metadata(),
                                ?error, "Couldn't decode public share",
                            );
                            metrics
                                .aggregate_step_failure_counter
                                .add(1, &[KeyValue::new("type", "public_share_decode_failure")]);
                            PrepareError::InvalidMessage
                        });

                        let shares =
                            input_share.and_then(|input_share| Ok((public_share?, input_share)));

                        // Reject reports from too far in the future.
                        let shares = shares.and_then(|shares| {
                            if prepare_init
                                .report_share()
                                .metadata()
                                .time()
                                .is_after(&report_deadline)
                            {
                                return Err(PrepareError::ReportTooEarly);
                            }
                            Ok(shares)
                        });

                        // Next, the aggregator runs the preparation-state initialization algorithm for the VDAF
                        // associated with the task and computes the first state transition. [...] If either
                        // step fails, then the aggregator MUST fail with error `vdaf-prep-error`. (§4.4.2.2)
                        let init_rslt = shares.and_then(|(public_share, input_share)| {
                            trace_span!("VDAF preparation (helper initialization)").in_scope(|| {
                                vdaf.helper_initialized(
                                    verify_key.as_bytes(),
                                    &agg_param,
                                    /* report ID is used as VDAF nonce */
                                    prepare_init.report_share().metadata().id().as_ref(),
                                    &public_share,
                                    &input_share,
                                    prepare_init.message(),
                                )
                                .and_then(|transition| transition.evaluate(&vdaf))
                                .map_err(|error| {
                                    handle_ping_pong_error(
                                        task.id(),
                                        Role::Helper,
                                        prepare_init.report_share().metadata().id(),
                                        error,
                                        &metrics.aggregate_step_failure_counter,
                                    )
                                })
                            })
                        });

                        let (report_aggregation_state, prepare_step_result, output_share) =
                            match init_rslt {
                                Ok((PingPongState::Continued(prepare_state), outgoing_message)) => {
                                    // Helper is not finished. Await the next message from the Leader to advance to
                                    // the next step.
                                    (
                                        ReportAggregationState::WaitingHelper { prepare_state },
                                        PrepareStepResult::Continue {
                                            message: outgoing_message,
                                        },
                                        None,
                                    )
                                }
                                Ok((PingPongState::Finished(output_share), outgoing_message)) => (
                                    ReportAggregationState::Finished,
                                    PrepareStepResult::Continue {
                                        message: outgoing_message,
                                    },
                                    Some(output_share),
                                ),
                                Err(prepare_error) => (
                                    ReportAggregationState::Failed { prepare_error },
                                    PrepareStepResult::Reject(prepare_error),
                                    None,
                                ),
                            };

                        sender.send(ReportShareData {
                            report_share: prepare_init.report_share().clone(),
                            report_aggregation: WritableReportAggregation::new(
                                ReportAggregation::<SEED_SIZE, A>::new(
                                    *task.id(),
                                    aggregation_job_id,
                                    *prepare_init.report_share().metadata().id(),
                                    *prepare_init.report_share().metadata().time(),
                                    // Unwrap safety: we checked that all ordinal values are representable
                                    // as a u64 before entering the parallel iterator.
                                    ord.try_into().unwrap(),
                                    Some(PrepareResp::new(
                                        *prepare_init.report_share().metadata().id(),
                                        prepare_step_result,
                                    )),
                                    report_aggregation_state,
                                ),
                                output_share,
                            ),
                        })
                    })
            }
        });

        let mut report_share_data = Vec::with_capacity(req.prepare_inits().len());
        while receiver.recv_many(&mut report_share_data, 10).await > 0 {}
        let report_share_data = Arc::new(report_share_data);

        // Await the producer task to resume any panics that may have occurred, and to ensure we can
        // unwrap the aggregation parameter's Arc in a few lines. The only other errors that can
        // occur are: a `JoinError` indicating cancellation, which is impossible because we do not
        // cancel the task; and a `SendError`, which can only happen if this future is cancelled (in
        // which case we will not run this code at all).
        let _ = producer_task.await.map_err(|join_error| {
            if let Ok(reason) = join_error.try_into_panic() {
                panic::resume_unwind(reason);
            }
        });
        assert_eq!(report_share_data.len(), req.prepare_inits().len());

        // Store data to datastore.
        let min_client_timestamp = req
            .prepare_inits()
            .iter()
            .map(|prepare_init| *prepare_init.report_share().metadata().time())
            .min()
            .ok_or_else(|| Error::EmptyAggregation(*task.id()))?;
        let max_client_timestamp = req
            .prepare_inits()
            .iter()
            .map(|prepare_init| *prepare_init.report_share().metadata().time())
            .max()
            .ok_or_else(|| Error::EmptyAggregation(*task.id()))?;
        let client_timestamp_interval = Interval::new(
            min_client_timestamp,
            max_client_timestamp
                .difference(&min_client_timestamp)?
                .add(&Duration::from_seconds(1))?,
        )?;
        let aggregation_job = Arc::new(
            AggregationJob::<SEED_SIZE, Q, A>::new(
                *task.id(),
                *aggregation_job_id,
                Arc::unwrap_or_clone(agg_param),
                req.batch_selector().batch_identifier().clone(),
                client_timestamp_interval,
                // For one-round VDAFs, the aggregation job will actually be finished, but the
                // aggregation job writer handles updating its state.
                AggregationJobState::InProgress,
                AggregationJobStep::from(0),
            )
            .with_last_request_hash(request_hash),
        );

        let (response, counters) = datastore
            .run_tx("aggregate_init", |tx| {
                let vdaf = Arc::clone(&vdaf);
                let task = Arc::clone(&task);
                let aggregation_job_writer_metrics = metrics.for_aggregation_job_writer();
                let aggregation_job = Arc::clone(&aggregation_job);
                let report_share_data = Arc::clone(&report_share_data);
                let req = Arc::clone(&req);
                let log_forbidden_mutations = log_forbidden_mutations.clone();

                Box::pin(async move {
                    // Check if this is a repeated request, and if it is the same as before, send
                    // the same response as last time. We check again to avoid the possibility of
                    // races.
                    if let Some(response) = Self::check_aggregate_init_idempotency(
                        tx,
                        vdaf.as_ref(),
                        task.id(),
                        aggregation_job.id(),
                        &req,
                        request_hash,
                        log_forbidden_mutations,
                    )
                    .await?
                    {
                        return Ok((response, TaskAggregationCounter::default()));
                    }

                    // Write report shares, and ensure this isn't a repeated report aggregation.
                    let report_aggregations = try_join_all(report_share_data.iter().map(|rsd| {
                        let task = Arc::clone(&task);

                        async move {
                            let mut report_aggregation = Cow::Borrowed(&rsd.report_aggregation);
                            match tx.put_scrubbed_report(task.id(), &rsd.report_share).await {
                                Ok(()) => (),
                                Err(datastore::Error::MutationTargetAlreadyExists) => {
                                    report_aggregation = Cow::Owned(
                                        report_aggregation
                                            .into_owned()
                                            .with_failure(PrepareError::ReportReplayed),
                                    )
                                }
                                Err(err) => return Err(err),
                            };
                            Ok(report_aggregation)
                        }
                    }))
                    .await?;

                    // Write aggregation job, report aggregations, and batch aggregations.
                    let mut aggregation_job_writer =
                        AggregationJobWriter::<SEED_SIZE, _, _, InitialWrite, _>::new(
                            task,
                            batch_aggregation_shard_count,
                            Some(aggregation_job_writer_metrics),
                        );
                    aggregation_job_writer
                        .put(aggregation_job.as_ref().clone(), report_aggregations)?;
                    let (mut prep_resps_by_agg_job, counters) =
                        aggregation_job_writer.write(tx, vdaf).await?;
                    Ok((
                        AggregationJobResp::new(
                            prep_resps_by_agg_job
                                .remove(aggregation_job.id())
                                .unwrap_or_default(),
                        ),
                        counters,
                    ))
                })
            })
            .await?;

        write_task_aggregation_counter(datastore, task_counter_shard_count, *task.id(), counters);

        Ok(response)
    }

    async fn handle_aggregate_continue_generic<
        const SEED_SIZE: usize,
        Q: AccumulableQueryType,
        A,
        C: Clock,
    >(
        datastore: Arc<Datastore<C>>,
        vdaf: Arc<A>,
        metrics: &AggregatorMetrics,
        task: Arc<AggregatorTask>,
        batch_aggregation_shard_count: u64,
        task_counter_shard_count: u64,
        aggregation_job_id: &AggregationJobId,
        req: Arc<AggregationJobContinueReq>,
        request_hash: [u8; 32],
    ) -> Result<AggregationJobResp, Error>
    where
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        A::AggregationParam: Send + Sync + PartialEq + Eq,
        A::AggregateShare: Send + Sync,
        A::InputShare: Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::PublicShare: Send + Sync,
        A::OutputShare: Send + Sync,
    {
        if req.step() == AggregationJobStep::from(0) {
            return Err(Error::InvalidMessage(
                Some(*task.id()),
                "aggregation job cannot be advanced to step 0",
            ));
        }

        // TODO(#224): don't hold DB transaction open while computing VDAF updates?
        // TODO(#1035): don't do O(n) network round-trips (where n is the number of prepare steps)
        let (response, counters) = datastore
            .run_tx("aggregate_continue", |tx| {
                let vdaf = Arc::clone(&vdaf);
                let metrics = metrics.clone();
                let task = Arc::clone(&task);
                let aggregation_job_id = *aggregation_job_id;
                let req = Arc::clone(&req);

                Box::pin(async move {
                    // Read existing state.
                    let (aggregation_job, report_aggregations) = try_join!(
                        tx.get_aggregation_job::<SEED_SIZE, Q, A>(task.id(), &aggregation_job_id),
                        tx.get_report_aggregations_for_aggregation_job(
                            vdaf.as_ref(),
                            &Role::Helper,
                            task.id(),
                            &aggregation_job_id,
                        )
                    )?;

                    let aggregation_job = aggregation_job.ok_or_else(|| {
                        datastore::Error::User(
                            Error::UnrecognizedAggregationJob(*task.id(), aggregation_job_id)
                                .into(),
                        )
                    })?;

                    // Deleted aggregation jobs cannot be stepped
                    if *aggregation_job.state() == AggregationJobState::Deleted {
                        return Err(datastore::Error::User(
                            Error::DeletedAggregationJob(*task.id(), *aggregation_job.id()).into(),
                        ));
                    }

                    // If the leader's request is on the same step as our stored aggregation job,
                    // then we probably have already received this message and computed this step,
                    // but the leader never got our response and so retried stepping the job.
                    // TODO(issue #1087): measure how often this happens with a Prometheus metric
                    if aggregation_job.step() == req.step() {
                        match aggregation_job.last_request_hash() {
                            None => {
                                return Err(datastore::Error::User(
                                    Error::Internal(format!(
                                        "aggregation job {aggregation_job_id} is on step {} but \
                                         has no last request hash",
                                        aggregation_job.step(),
                                    ))
                                    .into(),
                                ));
                            }
                            Some(previous_hash) => {
                                if request_hash != previous_hash {
                                    return Err(datastore::Error::User(
                                        Error::ForbiddenMutation {
                                            resource_type: "aggregation job continuation",
                                            identifier: aggregation_job_id.to_string(),
                                        }
                                        .into(),
                                    ));
                                }
                            }
                        }
                        return Ok((
                            AggregationJobResp::new(
                                report_aggregations
                                    .iter()
                                    .filter_map(ReportAggregation::last_prep_resp)
                                    .cloned()
                                    .collect(),
                            ),
                            TaskAggregationCounter::default(),
                        ));
                    } else if aggregation_job.step().increment() != req.step() {
                        // If this is not a replay, the leader should be advancing our state to the next
                        // step and no further.
                        return Err(datastore::Error::User(
                            Error::StepMismatch {
                                task_id: *task.id(),
                                aggregation_job_id,
                                expected_step: aggregation_job.step().increment(),
                                got_step: req.step(),
                            }
                            .into(),
                        ));
                    }

                    // The leader is advancing us to the next step. Step the aggregation job to
                    // compute the next round of prepare messages and state.
                    Self::step_aggregation_job(
                        tx,
                        task,
                        vdaf,
                        batch_aggregation_shard_count,
                        aggregation_job,
                        report_aggregations,
                        req,
                        request_hash,
                        &metrics,
                    )
                    .await
                })
            })
            .await?;

        write_task_aggregation_counter(datastore, task_counter_shard_count, *task.id(), counters);

        Ok(response)
    }

    /// Handle requests to the helper to delete an aggregation job.
    async fn handle_aggregate_delete_generic<
        const SEED_SIZE: usize,
        Q: AccumulableQueryType,
        A,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<(), Error>
    where
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> A::PrepareState: Send + Sync + Encode + ParameterizedDecode<(&'a A, usize)>,
        A::PrepareShare: Send + Sync,
        A::PrepareMessage: Send + Sync,
        A::OutputShare: Send + Sync,
    {
        Ok(datastore
            .run_tx("delete_aggregation_job", |tx| {
                let (task_id, aggregation_job_id) = (*task.id(), *aggregation_job_id);
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<SEED_SIZE, Q, A>(&task_id, &aggregation_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedAggregationJob(task_id, aggregation_job_id)
                                    .into(),
                            )
                        })?
                        .with_state(AggregationJobState::Deleted);

                    tx.update_aggregation_job(&aggregation_job).await?;

                    Ok(())
                })
            })
            .await?)
    }

    /// Handle requests to the leader to create a collection job.
    #[tracing::instrument(
        skip(self, datastore, task, collection_req_bytes),
        fields(task_id = ?task.id()),
        err(level = Level::DEBUG)
    )]
    async fn handle_create_collection_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        collection_job_id: &CollectionJobId,
        collection_req_bytes: &[u8],
    ) -> Result<(), Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_create_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id, collection_req_bytes)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_create_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id, collection_req_bytes)
                    .await
                })
            }
        }
    }

    async fn handle_create_collection_job_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        vdaf: Arc<A>,
        collection_job_id: &CollectionJobId,
        req_bytes: &[u8],
    ) -> Result<(), Error>
    where
        A::AggregationParam: 'static + Send + Sync + PartialEq + Eq + Hash,
        A::AggregateShare: Send + Sync,
    {
        let req =
            Arc::new(CollectionReq::<Q>::get_decoded(req_bytes).map_err(Error::MessageDecode)?);
        let aggregation_param = Arc::new(
            A::AggregationParam::get_decoded(req.aggregation_parameter())
                .map_err(Error::MessageDecode)?,
        );

        Ok(datastore
            .run_tx("collect", move |tx| {
                let (task, vdaf, collection_job_id, req, aggregation_param) = (
                    Arc::clone(&task),
                    Arc::clone(&vdaf),
                    *collection_job_id,
                    Arc::clone(&req),
                    Arc::clone(&aggregation_param),
                );
                Box::pin(async move {
                    // Check if this collection job already exists, ensuring that all parameters match.
                    if let Some(collection_job) = tx
                        .get_collection_job::<SEED_SIZE, Q, A>(&vdaf, task.id(), &collection_job_id)
                        .await?
                    {
                        if collection_job.query() == req.query()
                            && collection_job.aggregation_parameter() == aggregation_param.as_ref()
                        {
                            debug!(
                                collection_job_id = %collection_job_id,
                                collect_request = ?req,
                                "collection job already exists"
                            );
                            return Ok(());
                        } else {
                            return Err(datastore::Error::User(
                                Error::ForbiddenMutation {
                                    resource_type: "collection job",
                                    identifier: collection_job_id.to_string(),
                                }
                                .into(),
                            ));
                        }
                    }

                    let collection_identifier =
                        Q::collection_identifier_for_query(tx, &task, req.query())
                            .await?
                            .ok_or_else(|| {
                                datastore::Error::User(
                                    Error::BatchInvalid(
                                        *task.id(),
                                        "no batch ready for collection".to_string(),
                                    )
                                    .into(),
                                )
                            })?;

                    // Check that the batch interval is valid for the task
                    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6.1.1
                    if !Q::validate_collection_identifier(&task, &collection_identifier) {
                        return Err(datastore::Error::User(
                            Error::BatchInvalid(*task.id(), format!("{collection_identifier}"))
                                .into(),
                        ));
                    }

                    debug!(collect_request = ?req, "Cache miss, creating new collection job");
                    let (_, report_count) = try_join!(
                        Q::validate_query_count::<SEED_SIZE, C, A>(
                            tx,
                            &vdaf,
                            &task,
                            &collection_identifier,
                            &aggregation_param,
                        ),
                        Q::count_client_reports(tx, &task, &collection_identifier),
                    )?;

                    // Batch size must be validated while handling CollectReq and hence before
                    // creating a collection job.
                    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
                    if !task.validate_batch_size(report_count) {
                        return Err(datastore::Error::User(
                            Error::InvalidBatchSize(*task.id(), report_count).into(),
                        ));
                    }

                    tx.put_collection_job(&CollectionJob::<SEED_SIZE, Q, A>::new(
                        *task.id(),
                        collection_job_id,
                        req.query().clone(),
                        aggregation_param.as_ref().clone(),
                        collection_identifier,
                        CollectionJobState::Start,
                    ))
                    .await?;

                    Ok(())
                })
            })
            .await?)
    }

    /// Handle GET requests to the leader's `tasks/{task-id}/collection_jobs/{collection-job-id}`
    /// endpoint. The return value is an encoded `CollectResp<Q>`.
    /// <https://www.ietf.org/archive/id/draft-ietf-ppm-dap-07.html#name-collecting-results>
    #[tracing::instrument(skip(self, datastore, task), fields(task_id = ?task.id()), err(level = Level::DEBUG))]
    async fn handle_get_collection_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<Vec<u8>>, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_get_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_get_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
        }
    }

    // return value is an encoded CollectResp<Q>
    async fn handle_get_collection_job_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        vdaf: Arc<A>,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
    {
        let collection_job = datastore
            .run_tx("get_collection_job", |tx| {
                let (task, vdaf, collection_job_id) =
                    (Arc::clone(&task), Arc::clone(&vdaf), *collection_job_id);
                Box::pin(async move {
                    tx.get_collection_job::<SEED_SIZE, Q, A>(&vdaf, task.id(), &collection_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectionJob(*task.id(), collection_job_id)
                                    .into(),
                            )
                        })
                })
            })
            .await?;

        match collection_job.state() {
            CollectionJobState::Start => {
                debug!(%collection_job_id, task_id = %task.id(), "collection job has not run yet");
                Ok(None)
            }

            CollectionJobState::Finished {
                report_count,
                client_timestamp_interval,
                encrypted_helper_aggregate_share,
                leader_aggregate_share,
            } => {
                // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store the leader
                // aggregate share *unencrypted* in the datastore so that we can encrypt cached
                // results to the collector HPKE config valid when the current collection job request
                // was made, and not whatever was valid at the time the aggregate share was first
                // computed.
                // However we store the helper's *encrypted* share.

                // TODO(#240): consider fetching freshly encrypted helper aggregate share if it has
                // been long enough since the encrypted helper share was cached -- tricky thing is
                // deciding what "long enough" is.
                debug!(
                    %collection_job_id,
                    task_id = %task.id(),
                    "Serving cached collection job response"
                );
                let encrypted_leader_aggregate_share = hpke::seal(
                    // Unwrap safety: collector_hpke_config is only None for taskprov tasks. Taskprov
                    // is not currently supported for Janus operating as the Leader, so this unwrap
                    // is not reachable.
                    task.collector_hpke_config().unwrap(),
                    &HpkeApplicationInfo::new(
                        &Label::AggregateShare,
                        &Role::Leader,
                        &Role::Collector,
                    ),
                    &leader_aggregate_share
                        .get_encoded()
                        .map_err(Error::MessageEncode)?,
                    &AggregateShareAad::new(
                        *collection_job.task_id(),
                        collection_job
                            .aggregation_parameter()
                            .get_encoded()
                            .map_err(Error::MessageEncode)?,
                        BatchSelector::<Q>::new(collection_job.batch_identifier().clone()),
                    )
                    .get_encoded()
                    .map_err(Error::MessageEncode)?,
                )?;

                Ok(Some(
                    Collection::<Q>::new(
                        PartialBatchSelector::new(
                            Q::partial_batch_identifier(collection_job.batch_identifier()).clone(),
                        ),
                        *report_count,
                        *client_timestamp_interval,
                        encrypted_leader_aggregate_share,
                        encrypted_helper_aggregate_share.clone(),
                    )
                    .get_encoded()
                    .map_err(Error::MessageEncode)?,
                ))
            }

            CollectionJobState::Abandoned => Err(Error::AbandonedCollectionJob(
                *task.id(),
                *collection_job_id,
            )),

            CollectionJobState::Deleted => {
                Err(Error::DeletedCollectionJob(*task.id(), *collection_job_id))
            }
        }
    }

    #[tracing::instrument(skip(self, datastore, task), fields(task_id = ?task.id()), err(level = Level::DEBUG))]
    async fn handle_delete_collection_job<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        collection_job_id: &CollectionJobId,
    ) -> Result<(), Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_delete_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH) => {
                    Self::handle_delete_collection_job_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        VdafType,
                        _,
                    >(datastore, task, Arc::clone(vdaf), collection_job_id)
                    .await
                })
            }
        }
    }

    async fn handle_delete_collection_job_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        task: Arc<AggregatorTask>,
        vdaf: Arc<A>,
        collection_job_id: &CollectionJobId,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync + PartialEq + Eq,
    {
        datastore
            .run_tx("delete_collection_job", move |tx| {
                let (task, vdaf, collection_job_id) =
                    (Arc::clone(&task), Arc::clone(&vdaf), *collection_job_id);
                Box::pin(async move {
                    let collection_job = tx
                        .get_collection_job::<SEED_SIZE, Q, A>(
                            vdaf.as_ref(),
                            task.id(),
                            &collection_job_id,
                        )
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectionJob(*task.id(), collection_job_id)
                                    .into(),
                            )
                        })?;
                    if collection_job.state() != &CollectionJobState::Deleted {
                        tx.update_collection_job::<SEED_SIZE, Q, A>(
                            &collection_job.with_state(CollectionJobState::Deleted),
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    /// Implements the `tasks/{task-id}/aggregate_shares` endpoint for the helper.
    #[tracing::instrument(
        skip(self, datastore, clock, task, req_bytes),
        fields(task_id = ?task.id()),
        err(level = Level::DEBUG)
    )]
    async fn handle_aggregate_share<C: Clock>(
        &self,
        datastore: &Datastore<C>,
        clock: &C,
        task: Arc<AggregatorTask>,
        batch_aggregation_shard_count: u64,
        req_bytes: &[u8],
        collector_hpke_config: &HpkeConfig,
    ) -> Result<AggregateShare, Error> {
        match task.query_type() {
            task::QueryType::TimeInterval => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH, dp_strategy, DpStrategyType) => {
                    Self::handle_aggregate_share_generic::<
                        VERIFY_KEY_LENGTH,
                        TimeInterval,
                        DpStrategyType,
                        VdafType,
                        _,
                    >(datastore, clock, task, Arc::clone(vdaf), req_bytes, batch_aggregation_shard_count, collector_hpke_config, Arc::clone(dp_strategy)).await
                })
            }
            task::QueryType::FixedSize { .. } => {
                vdaf_ops_dispatch!(self, (vdaf, _, VdafType, VERIFY_KEY_LENGTH, dp_strategy, DpStrategyType) => {
                    Self::handle_aggregate_share_generic::<
                        VERIFY_KEY_LENGTH,
                        FixedSize,
                        DpStrategyType,
                        VdafType,
                        _,
                    >(datastore, clock, task, Arc::clone(vdaf), req_bytes, batch_aggregation_shard_count, collector_hpke_config, Arc::clone(dp_strategy)).await
                })
            }
        }
    }

    async fn handle_aggregate_share_generic<
        const SEED_SIZE: usize,
        Q: CollectableQueryType,
        S: DifferentialPrivacyStrategy + Send + Clone + Send + Sync + 'static,
        A: vdaf::AggregatorWithNoise<SEED_SIZE, 16, S> + Send + Sync + 'static,
        C: Clock,
    >(
        datastore: &Datastore<C>,
        clock: &C,
        task: Arc<AggregatorTask>,
        vdaf: Arc<A>,
        req_bytes: &[u8],
        batch_aggregation_shard_count: u64,
        collector_hpke_config: &HpkeConfig,
        dp_strategy: Arc<S>,
    ) -> Result<AggregateShare, Error>
    where
        A::AggregationParam: Send + Sync + Eq + Hash,
        A::AggregateShare: Send + Sync,
    {
        // Decode request, and verify that it is for the current task. We use an assert to check
        // that the task IDs match as this should be guaranteed by the caller.
        let aggregate_share_req =
            Arc::new(AggregateShareReq::<Q>::get_decoded(req_bytes).map_err(Error::MessageDecode)?);

        // §4.4.4.3: check that the batch interval meets the requirements from §4.6
        if !Q::validate_collection_identifier(
            &task,
            aggregate_share_req.batch_selector().batch_identifier(),
        ) {
            return Err(Error::BatchInvalid(
                *task.id(),
                format!(
                    "{}",
                    aggregate_share_req.batch_selector().batch_identifier()
                ),
            ));
        }

        // Reject requests for aggregation shares that are eligible for GC, to prevent replay
        // attacks.
        if let Some(report_expiry_age) = task.report_expiry_age() {
            if let Some(batch_interval) =
                Q::to_batch_interval(aggregate_share_req.batch_selector().batch_identifier())
            {
                let aggregate_share_expiry_time = batch_interval.end().add(report_expiry_age)?;
                if clock.now().is_after(&aggregate_share_expiry_time) {
                    return Err(Error::AggregateShareRequestRejected(
                        *task.id(),
                        "aggregate share request too late".to_string(),
                    ));
                }
            }
        }

        let aggregate_share_job = datastore
            .run_tx("aggregate_share", |tx| {
                let (task, vdaf, aggregate_share_req, dp_strategy) = (
                    Arc::clone(&task),
                    Arc::clone(&vdaf),
                    Arc::clone(&aggregate_share_req),
                    Arc::clone(&dp_strategy),
                );
                Box::pin(async move {
                    // Check if we have already serviced an aggregate share request with these
                    // parameters and serve the cached results if so.
                    let aggregation_param = A::AggregationParam::get_decoded(
                        aggregate_share_req.aggregation_parameter(),
                    )?;
                    if let Some(aggregate_share_job) = tx
                        .get_aggregate_share_job(
                            vdaf.as_ref(),
                            task.id(),
                            aggregate_share_req.batch_selector().batch_identifier(),
                            &aggregation_param,
                        )
                        .await?
                    {
                        debug!(
                            ?aggregate_share_req,
                            "Serving cached aggregate share job result"
                        );
                        return Ok(aggregate_share_job);
                    }

                    // This is a new aggregate share request, compute & validate the response.
                    debug!(
                        ?aggregate_share_req,
                        "Cache miss, computing aggregate share job result"
                    );
                    let aggregation_param = A::AggregationParam::get_decoded(
                        aggregate_share_req.aggregation_parameter(),
                    )?;
                    let (batch_aggregations, _) = try_join!(
                        Q::get_batch_aggregations_for_collection_identifier(
                            tx,
                            task.id(),
                            task.time_precision(),
                            vdaf.as_ref(),
                            aggregate_share_req.batch_selector().batch_identifier(),
                            &aggregation_param
                        ),
                        Q::validate_query_count::<SEED_SIZE, C, A>(
                            tx,
                            vdaf.as_ref(),
                            &task,
                            aggregate_share_req.batch_selector().batch_identifier(),
                            &aggregation_param,
                        )
                    )?;

                    // To ensure that concurrent aggregations don't write into a
                    // currently-nonexistent batch aggregation, we write (empty) batch
                    // aggregations for any that have not already been written to storage.
                    let empty_batch_aggregations = empty_batch_aggregations(
                        &task,
                        batch_aggregation_shard_count,
                        aggregate_share_req.batch_selector().batch_identifier(),
                        &aggregation_param,
                        &batch_aggregations,
                    );

                    let (mut helper_aggregate_share, report_count, _, checksum) =
                        compute_aggregate_share::<SEED_SIZE, Q, A>(&task, &batch_aggregations)
                            .await
                            .map_err(|e| datastore::Error::User(e.into()))?;

                    vdaf.add_noise_to_agg_share(
                        &dp_strategy,
                        &aggregation_param,
                        &mut helper_aggregate_share,
                        report_count.try_into()?,
                    )
                    .map_err(|e| datastore::Error::User(e.into()))?;

                    // Now that we are satisfied that the request is serviceable, we consume
                    // a query by recording the aggregate share request parameters and the
                    // result.
                    let aggregate_share_job = AggregateShareJob::<SEED_SIZE, Q, A>::new(
                        *task.id(),
                        aggregate_share_req
                            .batch_selector()
                            .batch_identifier()
                            .clone(),
                        aggregation_param,
                        helper_aggregate_share,
                        report_count,
                        checksum,
                    );
                    try_join!(
                        tx.put_aggregate_share_job(&aggregate_share_job),
                        try_join_all(batch_aggregations.into_iter().map(|ba| async move {
                            tx.update_batch_aggregation(&ba.scrubbed()).await
                        })),
                        try_join_all(empty_batch_aggregations.into_iter().map(|ba| async move {
                            tx.put_batch_aggregation(&ba.scrubbed()).await
                        }))
                    )?;
                    Ok(aggregate_share_job)
                })
            })
            .await?;

        // §4.4.4.3: Verify total report count and the checksum we computed against those reported
        // by the leader.
        if aggregate_share_job.report_count() != aggregate_share_req.report_count()
            || aggregate_share_job.checksum() != aggregate_share_req.checksum()
        {
            return Err(Error::BatchMismatch(Box::new(BatchMismatch {
                task_id: *task.id(),
                own_checksum: *aggregate_share_job.checksum(),
                own_report_count: aggregate_share_job.report_count(),
                peer_checksum: *aggregate_share_req.checksum(),
                peer_report_count: aggregate_share_req.report_count(),
            })));
        }

        // §4.4.4.3: HPKE encrypt aggregate share to the collector. We store *unencrypted* aggregate
        // shares in the datastore so that we can encrypt cached results to the collector HPKE
        // config valid when the current AggregateShareReq was made, and not whatever was valid at
        // the time the aggregate share was first computed.
        let encrypted_aggregate_share = hpke::seal(
            collector_hpke_config,
            &HpkeApplicationInfo::new(&Label::AggregateShare, &Role::Helper, &Role::Collector),
            &aggregate_share_job
                .helper_aggregate_share()
                .get_encoded()
                .map_err(Error::MessageEncode)?,
            &AggregateShareAad::new(
                *task.id(),
                aggregate_share_job
                    .aggregation_parameter()
                    .get_encoded()
                    .map_err(Error::MessageEncode)?,
                aggregate_share_req.batch_selector().clone(),
            )
            .get_encoded()
            .map_err(Error::MessageEncode)?,
        )?;

        Ok(AggregateShare::new(encrypted_aggregate_share))
    }
}

fn write_task_aggregation_counter<C: Clock>(
    datastore: Arc<Datastore<C>>,
    shard_count: u64,
    task_id: TaskId,
    counters: TaskAggregationCounter,
) {
    // We write task aggregation counters back in a separate tokio task & datastore transaction,
    // so that any slowness induced by writing the counters (e.g. due to transaction retry) does
    // not slow the main processing. The lack of transactionality between writing the updated
    // aggregation job & updating the counters means that process failure may cause us to leave
    // some counter updates unaccounted for, but that is an acceptable tradeoff.
    let ord = thread_rng().gen_range(0..shard_count);
    tokio::task::spawn(async move {
        let rslt = datastore
            .run_tx("update_task_aggregation_counters", |tx| {
                Box::pin(async move {
                    tx.increment_task_aggregation_counter(&task_id, ord, &counters)
                        .await
                })
            })
            .await;

        if let Err(err) = rslt {
            error!(
                ?task_id,
                ?err,
                "Couldn't increment task aggregation counter"
            );
        }
    });
}

fn empty_batch_aggregations<
    const SEED_SIZE: usize,
    Q: CollectableQueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
>(
    task: &AggregatorTask,
    batch_aggregation_shard_count: u64,
    batch_identifier: &Q::BatchIdentifier,
    aggregation_param: &A::AggregationParam,
    batch_aggregations: &[BatchAggregation<SEED_SIZE, Q, A>],
) -> Vec<BatchAggregation<SEED_SIZE, Q, A>> {
    let existing_batch_aggregations: HashSet<_> = batch_aggregations
        .iter()
        .map(|ba| (ba.batch_identifier(), ba.ord()))
        .collect();
    iproduct!(
        Q::batch_identifiers_for_collection_identifier(task.time_precision(), batch_identifier),
        0..batch_aggregation_shard_count
    )
    .filter_map(|(batch_identifier, ord)| {
        if !existing_batch_aggregations.contains(&(&batch_identifier, ord)) {
            Some(BatchAggregation::<SEED_SIZE, Q, A>::new(
                *task.id(),
                batch_identifier,
                aggregation_param.clone(),
                ord,
                Interval::EMPTY,
                BatchAggregationState::Collected {
                    aggregate_share: None,
                    report_count: 0,
                    checksum: ReportIdChecksum::default(),
                    aggregation_jobs_created: 0,
                    aggregation_jobs_terminated: 0,
                },
            ))
        } else {
            None
        }
    })
    .collect()
}

#[derive(Clone)]
struct RequestBody {
    content_type: &'static str,
    body: Bytes,
}

struct RequestTimer<'a> {
    // Mutable state.
    start: SyncMutex<Option<Instant>>,

    // Immutable state.
    http_request_duration_histogram: &'a Histogram<f64>,
    domain: Arc<str>,
    endpoint: &'static str,
    method: Arc<str>,
}

impl<'a> RequestTimer<'a> {
    fn new(
        http_request_duration_histogram: &'a Histogram<f64>,
        domain: Arc<str>,
        endpoint: &'static str,
        method: Arc<str>,
    ) -> Self {
        Self {
            start: SyncMutex::new(None),
            http_request_duration_histogram,
            domain,
            endpoint,
            method,
        }
    }

    fn start_attempt(&self) {
        *self.start.lock().unwrap() = Some(Instant::now())
    }

    fn finish_attempt(&self, status: &'static str) {
        let start = self
            .start
            .lock()
            .unwrap()
            .take()
            .expect("RequestTimer: finish_attempt called without calling start_attempt");
        self.http_request_duration_histogram.record(
            start.elapsed().as_secs_f64(),
            &[
                KeyValue::new("status", status),
                KeyValue::new("domain", Arc::clone(&self.domain)),
                KeyValue::new("endpoint", self.endpoint),
                KeyValue::new("method", Arc::clone(&self.method)),
            ],
        )
    }
}

impl<'a, E> Notify<E> for &RequestTimer<'a> {
    fn notify(&mut self, _: E, _: std::time::Duration) {
        self.finish_attempt("error")
    }
}

/// Convenience method to perform an HTTP request to the helper. This includes common
/// metrics and error handling functionality.
#[tracing::instrument(
    skip(
        http_client,
        backoff,
        url,
        request_body,
        auth_token,
        http_request_duration_histogram,
    ),
    fields(url = %url),
    err(level = Level::DEBUG),
)]
async fn send_request_to_helper(
    http_client: &Client,
    backoff: impl Backoff,
    method: Method,
    url: Url,
    route_label: &'static str,
    request_body: Option<RequestBody>,
    auth_token: &AuthenticationToken,
    http_request_duration_histogram: &Histogram<f64>,
) -> Result<Bytes, Error> {
    let (auth_header, auth_value) = auth_token.request_authentication();
    let domain = Arc::from(url.domain().unwrap_or_default());
    let method_str = Arc::from(method.as_str());
    let timer = RequestTimer::new(
        http_request_duration_histogram,
        domain,
        route_label,
        method_str,
    );

    let result = retry_http_request_notify(backoff, &timer, || async {
        timer.start_attempt();
        let mut request = http_client
            .request(method.clone(), url.clone())
            .header(auth_header, auth_value.as_str());
        if let Some(request_body) = request_body.clone() {
            request = request
                .header(CONTENT_TYPE, request_body.content_type)
                .body(request_body.body)
        };
        request.send().await
    })
    .await;

    match result {
        // Successful response.
        Ok(response) => {
            timer.finish_attempt("success");
            Ok(response.body().clone())
        }

        // HTTP-level error.
        Err(Ok(http_error_response)) => {
            timer.finish_attempt("error");
            Err(Error::Http(Box::new(http_error_response)))
        }

        // Network-level error.
        Err(Err(error)) => {
            timer.finish_attempt("error");
            Err(error.into())
        }
    }
}
