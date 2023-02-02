//! Implements portions of collect sub-protocol for DAP leader and helper.

use super::{aggregate_share::compute_aggregate_share, query_type::CollectableQueryType};
use crate::{
    aggregator::{post_to_helper, Error},
    datastore::{
        self,
        models::AcquiredCollectJob,
        models::{CollectJobState, Lease},
        Datastore,
    },
    task::{self, PRIO3_AES128_VERIFY_KEY_LENGTH},
    try_join,
};
use derivative::Derivative;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use futures::future::BoxFuture;
#[cfg(feature = "test-util")]
use janus_core::test_util::dummy_vdaf;
use janus_core::{task::VdafInstance, time::Clock};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    AggregateShareReq, AggregateShareResp, BatchSelector, Role,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, Unit},
    Context, KeyValue, Value,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3Aes128FixedPointBoundedL2VecSum;
use prio::{
    codec::{Decode, Encode},
    vdaf::{
        self,
        prio3::{
            Prio3Aes128Count, Prio3Aes128CountVecMultithreaded, Prio3Aes128Histogram,
            Prio3Aes128Sum,
        },
    },
};
use std::{sync::Arc, time::Duration};
use tracing::{info, warn};

/// Drives a collect job.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct CollectJobDriver {
    http_client: reqwest::Client,
    #[derivative(Debug = "ignore")]
    metrics: CollectJobDriverMetrics,
}

impl CollectJobDriver {
    /// Create a new [`CollectJobDriver`].
    pub fn new(http_client: reqwest::Client, meter: &Meter) -> Self {
        Self {
            http_client,
            metrics: CollectJobDriverMetrics::new(meter),
        }
    }

    /// Step the provided collect job, for which a lease should have been acquired (though this
    /// should be idempotent). If the collect job runs to completion, the leader share, helper
    /// share, report count and report ID checksum will be written to the `collect_jobs` table,
    /// and a subsequent request to the collect job URI will yield the aggregate shares. The collect
    /// job's lease is released, though it won't matter since the job will no longer be eligible to
    /// be run.
    ///
    /// If some error occurs (including a failure getting the helper's aggregate share), neither
    /// aggregate share is written to the datastore. A subsequent request to the collect job URI
    /// will not yield a result. The collect job lease will eventually expire, allowing a later run
    /// of the collect job driver to try again. Both aggregate shares will be recomputed at that
    /// time.
    pub async fn step_collect_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Arc<Lease<AcquiredCollectJob>>,
    ) -> Result<(), Error> {
        match (lease.leased().query_type(), lease.leased().vdaf()) {
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Count) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Count>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128CountVecMultithreaded>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Sum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Sum>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Histogram>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(
                    datastore,
                    lease,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafInstance::Fake) => {
                self.step_collect_job_generic::<0, C, TimeInterval, dummy_vdaf::Vdaf>(
                    datastore,
                    lease,
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Count) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Count>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128CountVecMultithreaded>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Sum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Sum>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Histogram>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(
                    datastore,
                    lease,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize{..}, VdafInstance::Fake) => {
                self.step_collect_job_generic::<0, C, FixedSize, dummy_vdaf::Vdaf>(
                    datastore,
                    lease,
                )
                .await
            }


            _ => panic!("VDAF {:?} is not yet supported", lease.leased().vdaf()),
        }
    }

    #[tracing::instrument(skip(self, datastore), err)]
    async fn step_collect_job_generic<
        const L: usize,
        C: Clock,
        Q: CollectableQueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Arc<Lease<AcquiredCollectJob>>,
    ) -> Result<(), Error>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: 'static + Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        A::OutputShare: PartialEq + Eq + Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let (task, collect_job, batch_aggregations) = datastore
            .run_tx_with_name("step_collect_job_1", |tx| {
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    // TODO(#224): Consider fleshing out `AcquiredCollectJob` to include a `Task`,
                    // `A::AggregationParam`, etc. so that we don't have to do more DB queries here.
                    let task = tx
                        .get_task(lease.leased().task_id())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedTask(*lease.leased().task_id()).into(),
                            )
                        })?;

                    let collect_job = tx
                        .get_collect_job::<L, Q, A>(lease.leased().collect_job_id())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(*lease.leased().collect_job_id())
                                    .into(),
                            )
                        })?;

                    let batch_aggregations = Q::get_batch_aggregations_for_collect_identifier(
                        tx,
                        &task,
                        collect_job.batch_identifier(),
                        collect_job.aggregation_parameter(),
                    )
                    .await?;

                    Ok((task, collect_job, batch_aggregations))
                })
            })
            .await?;

        if matches!(collect_job.state(), CollectJobState::Finished { .. }) {
            warn!("Collect job being stepped already has a computed helper share");
            self.metrics
                .jobs_already_finished_counter
                .add(&Context::current(), 1, &[]);
            return Ok(());
        }

        let (leader_aggregate_share, report_count, checksum) =
            compute_aggregate_share::<L, Q, A>(&task, &batch_aggregations)
                .await
                .map_err(|e| datastore::Error::User(e.into()))?;

        // Send an aggregate share request to the helper.
        let req = AggregateShareReq::<Q>::new(
            *task.id(),
            BatchSelector::new(collect_job.batch_identifier().clone()),
            collect_job.aggregation_parameter().get_encoded(),
            report_count,
            checksum,
        );

        let resp_bytes = post_to_helper(
            &self.http_client,
            task.aggregator_url(&Role::Helper)?
                .join("aggregate_share")?,
            AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            req,
            task.primary_aggregator_auth_token(),
            &self.metrics.http_request_duration_histogram,
        )
        .await?;

        // Store the helper aggregate share in the datastore so that a later request to a collect
        // job URI can serve it up.
        let collect_job = Arc::new(
            collect_job.with_state(CollectJobState::Finished {
                report_count,
                encrypted_helper_aggregate_share: AggregateShareResp::get_decoded(&resp_bytes)?
                    .encrypted_aggregate_share()
                    .clone(),
                leader_aggregate_share,
            }),
        );
        datastore
            .run_tx_with_name("step_collect_job_2", |tx| {
                let (lease, collect_job) = (Arc::clone(&lease), Arc::clone(&collect_job));
                let metrics = self.metrics.clone();

                Box::pin(async move {
                    let maybe_updated_collect_job = tx
                        .get_collect_job::<L, Q, A>(collect_job.collect_job_id())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(*collect_job.collect_job_id()).into(),
                            )
                        })?;

                    match maybe_updated_collect_job.state() {
                        CollectJobState::Start => {
                            tx.update_collect_job::<L, Q, A>(&collect_job).await?;
                            tx.release_collect_job(&lease).await?;
                            metrics.jobs_finished_counter.add(&Context::current(), 1, &[]);
                        }

                        CollectJobState::Deleted => {
                            // If the collect job was deleted between when we acquired it and now, discard
                            // the aggregate shares and leave the job in the deleted state so that
                            // appropriate status can be returned from polling the collect job URI and GC
                            // can run (#313).
                            info!(
                                collect_job_id = %collect_job.collect_job_id(),
                                "collect job was deleted while lease was held. Discarding aggregate results.",
                            );
                            metrics.deleted_jobs_encountered_counter.add(&Context::current(), 1, &[]);
                        }

                        state => {
                            // It shouldn't be possible for a collect job to move to the abandoned
                            // or finished state while this collect job driver held its lease.
                            metrics.unexpected_job_state_counter.add(&Context::current(), 1, &[KeyValue::new("state", Value::from(format!("{state}")))]);
                            panic!(
                                "collect job {} unexpectedly in state {}",
                                collect_job.collect_job_id(), state
                            );
                        }
                    }

                    Ok(())
                })
            })
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, datastore), err)]
    pub async fn abandon_collect_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredCollectJob>,
    ) -> Result<(), Error> {
        match (lease.leased().query_type(), lease.leased().vdaf()) {
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Count) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Count>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128CountVec{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128CountVecMultithreaded>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Sum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Sum>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128Histogram{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128Histogram>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::TimeInterval, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, TimeInterval, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(
                    datastore,
                    lease,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::TimeInterval, VdafInstance::Fake) => {
                self.abandon_collect_job_generic::<0, C, TimeInterval, dummy_vdaf::Vdaf>(
                    datastore,
                    lease,
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Count) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Count>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128CountVec{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128CountVecMultithreaded>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Sum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Sum>(
                    datastore,
                    lease
                )
                .await
            }

            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128Histogram{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128Histogram>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128FixedPoint16BitBoundedL2VecSum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI16<U15>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128FixedPoint32BitBoundedL2VecSum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI32<U31>>>(
                    datastore,
                    lease,
                )
                .await
            }

#[cfg(feature = "fpvec_bounded_l2")]
            (task::QueryType::FixedSize{..}, VdafInstance::Prio3Aes128FixedPoint64BitBoundedL2VecSum{..}) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, FixedSize, Prio3Aes128FixedPointBoundedL2VecSum<FixedI64<U63>>>(
                    datastore,
                    lease,
                )
                .await
            }

            #[cfg(feature = "test-util")]
            (task::QueryType::FixedSize{..}, VdafInstance::Fake) => {
                self.abandon_collect_job_generic::<0, C, FixedSize, dummy_vdaf::Vdaf>(
                    datastore,
                    lease,
                )
                .await
            }


            _ => panic!("VDAF {:?} is not yet supported", lease.leased().vdaf()),
        }
    }

    async fn abandon_collect_job_generic<
        const L: usize,
        C: Clock,
        Q: QueryType,
        A: vdaf::Aggregator<L>,
    >(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredCollectJob>,
    ) -> Result<(), Error>
    where
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Debug,
    {
        let lease = Arc::new(lease);
        datastore
            .run_tx_with_name("abandon_collect_job", |tx| {
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    let collect_job = tx
                        .get_collect_job::<L, Q, A>(lease.leased().collect_job_id())
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::DbState(format!(
                                "collect job {} was leased but no collect job was found",
                                lease.leased().collect_job_id(),
                            ))
                        })?
                        .with_state(CollectJobState::Abandoned);
                    let update_future = tx.update_collect_job(&collect_job);
                    let release_future = tx.release_collect_job(&lease);
                    try_join!(update_future, release_future)?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    /// Produce a closure for use as a `[JobDriver::JobAcquirer`].
    pub fn make_incomplete_job_acquirer_callback<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease_duration: Duration,
    ) -> impl Fn(usize) -> BoxFuture<'static, Result<Vec<Lease<AcquiredCollectJob>>, datastore::Error>>
    {
        move |maximum_acquire_count_per_query_type| {
            let datastore = Arc::clone(&datastore);
            Box::pin(async move {
                datastore
                    .run_tx_with_name("acquire_collect_jobs", |tx| {
                        Box::pin(async move {
                            let (time_interval_jobs, fixed_size_jobs) = try_join!(
                                tx.acquire_incomplete_time_interval_collect_jobs(
                                    &lease_duration,
                                    maximum_acquire_count_per_query_type,
                                ),
                                tx.acquire_incomplete_fixed_size_collect_jobs(
                                    &lease_duration,
                                    maximum_acquire_count_per_query_type
                                ),
                            )?;
                            Ok(time_interval_jobs
                                .into_iter()
                                .chain(fixed_size_jobs.into_iter())
                                .collect())
                        })
                    })
                    .await
            })
        }
    }

    /// Produce a closure for use as a `[JobDriver::JobStepper]`.
    pub fn make_job_stepper_callback<C: Clock>(
        self: Arc<Self>,
        datastore: Arc<Datastore<C>>,
        maximum_attempts_before_failure: usize,
    ) -> impl Fn(Lease<AcquiredCollectJob>) -> BoxFuture<'static, Result<(), super::Error>> {
        move |collect_job_lease: Lease<AcquiredCollectJob>| {
            let (this, datastore) = (Arc::clone(&self), Arc::clone(&datastore));
            Box::pin(async move {
                if collect_job_lease.lease_attempts() > maximum_attempts_before_failure {
                    warn!(
                        attempts = %collect_job_lease.lease_attempts(),
                        max_attempts = %maximum_attempts_before_failure,
                        "Abandoning job due to too many failed attempts"
                    );
                    this.metrics
                        .jobs_abandoned_counter
                        .add(&Context::current(), 1, &[]);
                    return this.abandon_collect_job(datastore, collect_job_lease).await;
                }

                this.step_collect_job(datastore, Arc::new(collect_job_lease))
                    .await
            })
        }
    }
}

/// Holds various metrics instruments for a collect job driver.
#[derive(Clone)]
struct CollectJobDriverMetrics {
    jobs_finished_counter: Counter<u64>,
    http_request_duration_histogram: Histogram<f64>,
    jobs_abandoned_counter: Counter<u64>,
    jobs_already_finished_counter: Counter<u64>,
    deleted_jobs_encountered_counter: Counter<u64>,
    unexpected_job_state_counter: Counter<u64>,
}

impl CollectJobDriverMetrics {
    fn new(meter: &Meter) -> Self {
        let jobs_finished_counter = meter
            .u64_counter("janus_collect_jobs_finished")
            .with_description("Count of finished collect jobs.")
            .init();
        jobs_finished_counter.add(&Context::current(), 0, &[]);

        let http_request_duration_histogram = meter
            .f64_histogram("janus_http_request_duration_seconds")
            .with_description(
                "The amount of time elapsed while making an HTTP request to a helper.",
            )
            .with_unit(Unit::new("seconds"))
            .init();

        let jobs_abandoned_counter = meter
            .u64_counter("janus_collect_jobs_abandoned")
            .with_description("Count of abandoned collect jobs.")
            .init();
        jobs_abandoned_counter.add(&Context::current(), 0, &[]);

        let jobs_already_finished_counter = meter
            .u64_counter("janus_collect_jobs_already_finished")
            .with_description(
                "Count of collect jobs for which a lease was acquired but were already finished.",
            )
            .init();
        jobs_already_finished_counter.add(&Context::current(), 0, &[]);

        let deleted_jobs_encountered_counter = meter
            .u64_counter("janus_collect_deleted_jobs_encountered")
            .with_description(
                "Count of collect jobs that were run to completion but found to have been deleted.",
            )
            .init();
        deleted_jobs_encountered_counter.add(&Context::current(), 0, &[]);

        let unexpected_job_state_counter = meter
            .u64_counter("janus_collect_unexpected_job_state")
            .with_description("Count of collect jobs that were run to completion but found in an unexpected state.").init();
        unexpected_job_state_counter.add(&Context::current(), 0, &[]);

        Self {
            jobs_finished_counter,
            http_request_duration_histogram,
            jobs_abandoned_counter,
            jobs_already_finished_counter,
            deleted_jobs_encountered_counter,
            unexpected_job_state_counter,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aggregator::{collect_job_driver::CollectJobDriver, DapProblemType, Error},
        binary_utils::job_driver::JobDriver,
        datastore::{
            models::{
                AcquiredCollectJob, AggregationJob, AggregationJobState, BatchAggregation,
                CollectJob, CollectJobState, LeaderStoredReport, Lease, ReportAggregation,
                ReportAggregationState,
            },
            test_util::ephemeral_datastore,
            Datastore,
        },
        messages::TimeExt,
        task::{test_util::TaskBuilder, QueryType},
    };
    use assert_matches::assert_matches;
    use http::{header::CONTENT_TYPE, StatusCode};
    use janus_core::{
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregateShare, AggregationParam, OutputShare},
            install_test_trace_subscriber,
            runtime::TestRuntimeManager,
        },
        time::{Clock, MockClock, TimeExt as CoreTimeExt},
        Runtime,
    };
    use janus_messages::{
        query_type::TimeInterval, AggregateShareReq, AggregateShareResp, BatchSelector, Duration,
        HpkeCiphertext, HpkeConfigId, Interval, ReportIdChecksum, Role,
    };
    use mockito::mock;
    use opentelemetry::global::meter;
    use prio::codec::{Decode, Encode};
    use rand::random;
    use std::{str, sync::Arc, time::Duration as StdDuration};
    use url::Url;
    use uuid::Uuid;

    async fn setup_collect_job_test_case(
        clock: MockClock,
        datastore: Arc<Datastore<MockClock>>,
        acquire_lease: bool,
    ) -> (
        Option<Lease<AcquiredCollectJob>>,
        CollectJob<0, TimeInterval, dummy_vdaf::Vdaf>,
    ) {
        let time_precision = Duration::from_seconds(500);
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
            .with_aggregator_endpoints(Vec::from([
                Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
                Url::parse(&mockito::server_url()).unwrap(),
            ]))
            .with_time_precision(time_precision)
            .with_min_batch_size(10)
            .build();
        let batch_interval = Interval::new(clock.now(), Duration::from_seconds(2000)).unwrap();
        let aggregation_param = AggregationParam(0);

        let collect_job = CollectJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
            *task.id(),
            Uuid::new_v4(),
            batch_interval,
            aggregation_param,
            CollectJobState::Start,
        );

        let lease = datastore
            .run_tx(|tx| {
                let (clock, task, collect_job) = (clock.clone(), task.clone(), collect_job.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&collect_job)
                        .await?;

                    let aggregation_job_id = random();
                    let report_timestamp = clock
                        .now()
                        .to_batch_interval_start(task.time_precision())
                        .unwrap();
                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            aggregation_job_id,
                            aggregation_param,
                            (),
                            Interval::new(report_timestamp, Duration::from_seconds(1)).unwrap(),
                            AggregationJobState::Finished,
                        ),
                    )
                    .await?;

                    let report = LeaderStoredReport::new_dummy(*task.id(), report_timestamp);

                    tx.put_client_report(&report).await?;

                    tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        *report.metadata().time(),
                        0,
                        ReportAggregationState::Finished(OutputShare()),
                    ))
                    .await?;

                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            Interval::new(clock.now(), time_precision).unwrap(),
                            aggregation_param,
                            AggregateShare(0),
                            5,
                            ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                        ),
                    )
                    .await?;
                    tx.put_batch_aggregation(
                        &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            Interval::new(
                                clock.now().add(&Duration::from_seconds(1000)).unwrap(),
                                time_precision,
                            )
                            .unwrap(),
                            aggregation_param,
                            AggregateShare(0),
                            5,
                            ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                        ),
                    )
                    .await?;

                    if acquire_lease {
                        let lease = tx
                            .acquire_incomplete_time_interval_collect_jobs(
                                &StdDuration::from_secs(100),
                                1,
                            )
                            .await?
                            .remove(0);
                        assert_eq!(task.id(), lease.leased().task_id());
                        assert_eq!(
                            collect_job.collect_job_id(),
                            lease.leased().collect_job_id()
                        );
                        Ok(Some(lease))
                    } else {
                        Ok(None)
                    }
                })
            })
            .await
            .unwrap();

        (lease, collect_job)
    }

    #[tokio::test]
    async fn drive_collect_job() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let time_precision = Duration::from_seconds(500);
        let task = TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake, Role::Leader)
            .with_aggregator_endpoints(Vec::from([
                Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
                Url::parse(&mockito::server_url()).unwrap(),
            ]))
            .with_time_precision(time_precision)
            .with_min_batch_size(10)
            .build();
        let agg_auth_token = task.primary_aggregator_auth_token();
        let batch_interval = Interval::new(clock.now(), Duration::from_seconds(2000)).unwrap();
        let aggregation_param = AggregationParam(0);

        let (collect_job_id, lease) = ds
            .run_tx(|tx| {
                let (clock, task) = (clock.clone(), task.clone());
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    let collect_job_id = Uuid::new_v4();
                    tx.put_collect_job(&CollectJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        collect_job_id,
                        batch_interval,
                        aggregation_param,
                        CollectJobState::Start,
                    ))
                    .await?;

                    let aggregation_job_id = random();
                    let report_timestamp = clock
                        .now()
                        .to_batch_interval_start(task.time_precision())
                        .unwrap();
                    tx.put_aggregation_job(
                        &AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                            *task.id(),
                            aggregation_job_id,
                            aggregation_param,
                            (),
                            Interval::new(report_timestamp, Duration::from_seconds(1)).unwrap(),
                            AggregationJobState::Finished,
                        ),
                    )
                    .await?;

                    let report = LeaderStoredReport::new_dummy(*task.id(), report_timestamp);

                    tx.put_client_report(&report).await?;

                    tx.put_report_aggregation(&ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        aggregation_job_id,
                        *report.metadata().id(),
                        *report.metadata().time(),
                        0,
                        ReportAggregationState::Finished(OutputShare()),
                    ))
                    .await?;

                    let lease = Arc::new(
                        tx.acquire_incomplete_time_interval_collect_jobs(
                            &StdDuration::from_secs(100),
                            1,
                        )
                        .await?
                        .remove(0),
                    );

                    assert_eq!(task.id(), lease.leased().task_id());
                    assert_eq!(&collect_job_id, lease.leased().collect_job_id());
                    Ok((collect_job_id, lease))
                })
            })
            .await
            .unwrap();

        let collect_job_driver = CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &meter("collect_job_driver"),
        );

        // No batch aggregations inserted yet.
        let error = collect_job_driver
            .step_collect_job(ds.clone(), Arc::clone(&lease))
            .await
            .unwrap_err();
        assert_matches!(error, Error::InvalidBatchSize(error_task_id, 0) => {
            assert_eq!(task.id(), &error_task_id)
        });

        // Put some batch aggregations in the DB.
        ds.run_tx(|tx| {
            let (clock, task) = (clock.clone(), task.clone());
            Box::pin(async move {
                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(clock.now(), time_precision).unwrap(),
                        aggregation_param,
                        AggregateShare(0),
                        5,
                        ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                    ),
                )
                .await?;

                tx.put_batch_aggregation(
                    &BatchAggregation::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Interval::new(
                            clock.now().add(&Duration::from_seconds(1000)).unwrap(),
                            time_precision,
                        )
                        .unwrap(),
                        aggregation_param,
                        AggregateShare(0),
                        5,
                        ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                    ),
                )
                .await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        let leader_request = AggregateShareReq::new(
            *task.id(),
            BatchSelector::new_time_interval(batch_interval),
            aggregation_param.get_encoded(),
            10,
            ReportIdChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
        );

        // Simulate helper failing to service the aggregate share request.
        let mocked_failed_aggregate_share = mock("POST", "/aggregate_share")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(
                CONTENT_TYPE.as_str(),
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_body(leader_request.get_encoded())
            .with_status(500)
            .with_header("Content-Type", "application/problem+json")
            .with_body("{\"type\": \"urn:ietf:params:ppm:dap:error:batchQueriedTooManyTimes\"}")
            .create();

        let error = collect_job_driver
            .step_collect_job(ds.clone(), Arc::clone(&lease))
            .await
            .unwrap_err();
        assert_matches!(
            error,
            Error::Http {
                problem_details,
                dap_problem_type: Some(DapProblemType::BatchQueriedTooManyTimes),
            } => {
                assert_eq!(problem_details.status.unwrap(), StatusCode::INTERNAL_SERVER_ERROR);
            }
        );

        mocked_failed_aggregate_share.assert();

        // Collect job in datastore should be unchanged.
        ds.run_tx(|tx| {
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&collect_job_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(collect_job.state(), &CollectJobState::Start);
                Ok(())
            })
        })
        .await
        .unwrap();

        // Helper aggregate share is opaque to the leader, so no need to construct a real one
        let helper_response = AggregateShareResp::new(HpkeCiphertext::new(
            HpkeConfigId::from(100),
            Vec::new(),
            Vec::new(),
        ));

        let mocked_aggregate_share = mock("POST", "/aggregate_share")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(
                CONTENT_TYPE.as_str(),
                AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            )
            .match_body(leader_request.get_encoded())
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), AggregateShareResp::MEDIA_TYPE)
            .with_body(helper_response.get_encoded())
            .create();

        collect_job_driver
            .step_collect_job(ds.clone(), Arc::clone(&lease))
            .await
            .unwrap();

        mocked_aggregate_share.assert();

        // Should now have recorded helper encrypted aggregate share, too.
        ds.run_tx(|tx| {
            let helper_aggregate_share = helper_response.encrypted_aggregate_share().clone();
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&collect_job_id)
                    .await
                    .unwrap()
                    .unwrap();

                assert_matches!(collect_job.state(), CollectJobState::Finished{ encrypted_helper_aggregate_share, .. } => {
                    assert_eq!(encrypted_helper_aggregate_share, &helper_aggregate_share);
                });

                Ok(())
            })
        })
        .await
        .unwrap();

        // Drive collect job again. It should succeed without contacting the helper.
        collect_job_driver
            .step_collect_job(ds.clone(), lease)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn abandon_collect_job() {
        // Setup: insert a collect job into the datastore.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let (lease, collect_job) = setup_collect_job_test_case(clock, Arc::clone(&ds), true).await;

        let collect_job_driver = CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &meter("collect_job_driver"),
        );

        // Run: abandon the collect job.
        collect_job_driver
            .abandon_collect_job(Arc::clone(&ds), lease.unwrap())
            .await
            .unwrap();

        // Verify: check that the collect job was abandoned, and that it can no longer be acquired.
        let (abandoned_collect_job, leases) = ds
            .run_tx(|tx| {
                let collect_job = collect_job.clone();
                Box::pin(async move {
                    let abandoned_collect_job = tx
                        .get_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            collect_job.collect_job_id(),
                        )
                        .await?
                        .unwrap();

                    let leases = tx
                        .acquire_incomplete_time_interval_collect_jobs(
                            &StdDuration::from_secs(100),
                            1,
                        )
                        .await?;

                    Ok((abandoned_collect_job, leases))
                })
            })
            .await
            .unwrap();
        assert_eq!(
            abandoned_collect_job,
            collect_job.with_state(CollectJobState::Abandoned),
        );
        assert!(leases.is_empty());
    }

    #[tokio::test]
    async fn abandon_failing_collect_job() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let mut runtime_manager = TestRuntimeManager::new();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let (_, collect_job) =
            setup_collect_job_test_case(clock.clone(), Arc::clone(&ds), false).await;

        // Set up the collect job driver
        let meter = meter("collect_job_driver");
        let collect_job_driver = Arc::new(CollectJobDriver::new(reqwest::Client::new(), &meter));
        let job_driver = Arc::new(JobDriver::new(
            clock.clone(),
            runtime_manager.with_label("stepper"),
            meter,
            StdDuration::from_secs(1),
            StdDuration::from_secs(1),
            10,
            StdDuration::from_secs(60),
            collect_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&ds),
                StdDuration::from_secs(600),
            ),
            collect_job_driver.make_job_stepper_callback(Arc::clone(&ds), 3),
        ));

        // Set up three error responses from our mock helper. These will cause errors in the
        // leader, because the response body is empty and cannot be decoded.
        let failure_mock = mock("POST", "/aggregate_share")
            .with_status(500)
            .expect(3)
            .create();
        // Set up an extra response that should never be used, to make sure the job driver doesn't
        // make more requests than we expect. If there were no remaining mocks, mockito would have
        // respond with a fallback error response instead.
        let no_more_requests_mock = mock("POST", "/aggregate_share")
            .with_status(500)
            .expect(1)
            .create();

        // Start up the job driver.
        let task_handle = runtime_manager
            .with_label("driver")
            .spawn(async move { job_driver.run().await });

        // Run the job driver until we try to step the collect job four times. The first three
        // attempts make network requests and fail, while the fourth attempt just marks the job
        // as abandoned.
        for i in 1..=4 {
            // Wait for the next task to be spawned and to complete.
            runtime_manager.wait_for_completed_tasks("stepper", i).await;
            // Advance the clock by the lease duration, so that the job driver can pick up the job
            // and try again.
            clock.advance(Duration::from_seconds(600));
        }
        // Shut down the job driver.
        task_handle.abort();

        // Check that the job driver made the HTTP requests we expected.
        failure_mock.assert();
        assert!(!no_more_requests_mock.matched());

        // Confirm that the collect job was abandoned.
        let collect_job_after = ds
            .run_tx(|tx| {
                let collect_job = collect_job.clone();
                Box::pin(async move {
                    tx.get_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        collect_job.collect_job_id(),
                    )
                    .await
                })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            collect_job_after,
            collect_job.with_state(CollectJobState::Abandoned),
        );
    }

    #[tokio::test]
    async fn delete_collect_job() {
        // Setup: insert a collect job into the datastore.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let (lease, collect_job) = setup_collect_job_test_case(clock, Arc::clone(&ds), true).await;

        // Delete the collect job
        let collect_job = collect_job.with_state(CollectJobState::Deleted);

        ds.run_tx(|tx| {
            let collect_job = collect_job.clone();
            Box::pin(async move {
                tx.update_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(&collect_job)
                    .await
            })
        })
        .await
        .unwrap();

        // Helper aggregate share is opaque to the leader, so no need to construct a real one
        let helper_response = AggregateShareResp::new(HpkeCiphertext::new(
            HpkeConfigId::from(100),
            Vec::new(),
            Vec::new(),
        ));

        let mocked_aggregate_share = mock("POST", "/aggregate_share")
            .with_status(200)
            .with_header(CONTENT_TYPE.as_str(), AggregateShareResp::MEDIA_TYPE)
            .with_body(helper_response.get_encoded())
            .create();

        let collect_job_driver = CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &meter("collect_job_driver"),
        );

        // Step the collect job. The driver should successfully run the job, but then discard the
        // results when it notices the job has been deleted.
        collect_job_driver
            .step_collect_job(ds.clone(), Arc::new(lease.unwrap()))
            .await
            .unwrap();

        mocked_aggregate_share.assert();

        // Verify: check that the collect job was abandoned, and that it can no longer be acquired.
        ds.run_tx(|tx| {
            let collect_job = collect_job.clone();
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<0, TimeInterval, dummy_vdaf::Vdaf>(
                        collect_job.collect_job_id(),
                    )
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(collect_job.state(), &CollectJobState::Deleted);

                let leases = tx
                    .acquire_incomplete_time_interval_collect_jobs(&StdDuration::from_secs(100), 1)
                    .await
                    .unwrap();

                assert!(leases.is_empty());

                Ok(())
            })
        })
        .await
        .unwrap();
    }
}
