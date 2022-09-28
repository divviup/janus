//! Implements portions of collect sub-protocol for DAP leader and helper.

use crate::{
    aggregator::{post_to_helper, Error},
    datastore::{
        self,
        models::AcquiredCollectJob,
        models::{BatchUnitAggregation, CollectJobState, Lease},
        Datastore, Transaction,
    },
    task::{Task, VdafInstance, PRIO3_AES128_VERIFY_KEY_LENGTH},
};
use derivative::Derivative;
use futures::{future::BoxFuture, try_join};
#[cfg(test)]
use janus_core::test_util::dummy_vdaf;
use janus_core::{report_id::ReportIdChecksumExt, time::Clock};
use janus_messages::{
    query_type::TimeInterval, AggregateShareReq, AggregateShareResp, BatchSelector, Duration,
    Interval, ReportIdChecksum, Role,
};
use opentelemetry::{
    metrics::{Counter, Histogram, Meter, Unit},
    Context, KeyValue, Value,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::{
        self,
        prio3::{
            Prio3Aes128Count, Prio3Aes128CountVecMultithreaded, Prio3Aes128Histogram,
            Prio3Aes128Sum,
        },
        Aggregatable,
    },
};
use std::{borrow::Borrow, sync::Arc};
use tracing::{debug, error, info, warn};

#[cfg(test)]
const DUMMY_VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

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
        lease: Lease<AcquiredCollectJob>,
    ) -> Result<(), Error> {
        match lease.leased().vdaf {
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128Count>(
                    datastore,
                    lease
                )
                .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128CountVecMultithreaded>(
                    datastore,
                    lease
                )
                .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128Sum>(
                    datastore,
                    lease
                )
                .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.step_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128Histogram>(
                    datastore,
                    lease,
                )
                .await
            }

            #[cfg(test)]
            VdafInstance::Fake => {
                self.step_collect_job_generic::<DUMMY_VERIFY_KEY_LENGTH, C, dummy_vdaf::Vdaf>(
                    datastore,
                    lease,
                )
                .await
            }

            _ => panic!("VDAF {:?} is not yet supported", lease.leased().vdaf),
        }
    }

    #[tracing::instrument(skip(self, datastore), err)]
    async fn step_collect_job_generic<const L: usize, C: Clock, A: vdaf::Aggregator<L>>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredCollectJob>,
    ) -> Result<(), Error>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: 'static + Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        A::OutputShare: PartialEq + Eq + Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = lease.leased().task_id;
        let collect_job_id = lease.leased().collect_job_id;
        let (task, mut collect_job, batch_unit_aggregations) = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    // TODO(#224): Consider fleshing out `AcquiredCollectJob` to include a `Task`,
                    // `A::AggregationParam`, etc. so that we don't have to do more DB queries here.
                    let task = tx.get_task(task_id).await?.ok_or_else(|| {
                        datastore::Error::User(Error::UnrecognizedTask(task_id).into())
                    })?;

                    let collect_job = tx
                        .get_collect_job::<L, A>(collect_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(collect_job_id).into(),
                            )
                        })?;

                    let batch_unit_aggregations = tx
                        .get_batch_unit_aggregations_for_task_in_interval::<L, A>(
                            task.id,
                            collect_job.batch_interval,
                            &collect_job.aggregation_param,
                        )
                        .await?;

                    Ok((task, collect_job, batch_unit_aggregations))
                })
            })
            .await?;

        if matches!(collect_job.state, CollectJobState::Finished { .. }) {
            warn!("Collect job being stepped already has a computed helper share");
            self.metrics
                .jobs_already_finished_counter
                .add(&Context::current(), 1, &[]);
            return Ok(());
        }

        let (leader_aggregate_share, report_count, checksum) =
            compute_aggregate_share::<L, A>(&task, &batch_unit_aggregations)
                .await
                .map_err(|e| datastore::Error::User(e.into()))?;

        // Send an aggregate share request to the helper.
        let req = AggregateShareReq::new(
            task.id,
            BatchSelector::new_time_interval(collect_job.batch_interval),
            collect_job.aggregation_param.get_encoded(),
            report_count,
            checksum,
        );

        let resp_bytes = post_to_helper(
            &self.http_client,
            task.aggregator_url(Role::Helper)?.join("aggregate_share")?,
            AggregateShareReq::<TimeInterval>::MEDIA_TYPE,
            req,
            task.primary_aggregator_auth_token(),
            &self.metrics.http_request_duration_histogram,
        )
        .await?;

        // Store the helper aggregate share in the datastore so that a later request to a collect
        // job URI can serve it up.
        let aggregate_share_resp = AggregateShareResp::get_decoded(&resp_bytes)?;

        collect_job.state = CollectJobState::Finished {
            encrypted_helper_aggregate_share: aggregate_share_resp
                .encrypted_aggregate_share()
                .clone(),
            leader_aggregate_share,
        };

        let lease = Arc::new(lease);
        let collect_job = Arc::new(collect_job);
        datastore
            .run_tx(|tx| {
                let lease = Arc::clone(&lease);
                let collect_job = Arc::clone(&collect_job);
                let metrics = self.metrics.clone();

                Box::pin(async move {
                    let maybe_updated_collect_job = tx
                        .get_collect_job::<L, A>(collect_job.id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(collect_job_id).into(),
                            )
                        })?;

                    match maybe_updated_collect_job.state {
                        CollectJobState::Start => {
                            tx.update_collect_job::<L, A>(collect_job.borrow()).await?;
                            tx.release_collect_job(&lease).await?;
                            metrics.jobs_finished_counter.add(&Context::current(), 1, &[]);
                        }
                        CollectJobState::Deleted => {
                            // If the collect job was deleted between when we acquired it and now, discard
                            // the aggregate shares and leave the job in the deleted state so that
                            // appropriate status can be returned from polling the collect job URI and GC
                            // can run (#313).
                            info!(
                                "collect job {} was deleted while lease was held. Discarding aggregate results.",
                                collect_job.id,
                            );
                            metrics.deleted_jobs_encountered_counter.add(&Context::current(), 1, &[]);
                        }
                        state => {
                            // It shouldn't be possible for a collect job to move to the abandoned
                            // or finished state while this collect job driver held its lease.
                            metrics.unexpected_job_state_counter.add(&Context::current(), 1, &[KeyValue::new("state", Value::from(format!("{state}")))]);
                            panic!(
                                "collect job {} unexpectedly in state {}",
                                collect_job.id, state
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
        match lease.leased().vdaf {
            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128Count>(
                    datastore,
                    lease
                )
                .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128CountVec { .. }) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128CountVecMultithreaded>(
                    datastore,
                    lease
                )
                .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { .. }) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128Sum>(
                    datastore,
                    lease
                )
                .await
            }

            VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram { .. }) => {
                self.abandon_collect_job_generic::<PRIO3_AES128_VERIFY_KEY_LENGTH, C, Prio3Aes128Histogram>(
                    datastore,
                    lease,
                )
                .await
            }

            #[cfg(test)]
            VdafInstance::Fake => {
                self.abandon_collect_job_generic::<DUMMY_VERIFY_KEY_LENGTH, C, dummy_vdaf::Vdaf>(
                    datastore,
                    lease,
                )
                .await
            }

            _ => panic!("VDAF {:?} is not yet supported", lease.leased().vdaf),
        }
    }

    async fn abandon_collect_job_generic<const L: usize, C, A>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredCollectJob>,
    ) -> Result<(), Error>
    where
        C: Clock,
        A: vdaf::Aggregator<L> + 'static,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    {
        let collect_job_id = lease.leased().collect_job_id;
        let lease = Arc::new(lease);
        datastore
            .run_tx(|tx| {
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    let mut collect_job = tx
                        .get_collect_job::<L, A>(collect_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::DbState(format!(
                                "collect job {} was leased but no collect job was found",
                                collect_job_id,
                            ))
                        })?;
                    collect_job.state = CollectJobState::Abandoned;
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
        move |maximum_acquire_count| {
            let datastore = Arc::clone(&datastore);
            Box::pin(async move {
                datastore
                    .run_tx(|tx| {
                        Box::pin(async move {
                            tx.acquire_incomplete_collect_jobs(
                                lease_duration,
                                maximum_acquire_count,
                            )
                            .await
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
                        attempts = ?collect_job_lease.lease_attempts(),
                        max_attempts = ?maximum_attempts_before_failure,
                        "Abandoning job due to too many failed attempts"
                    );
                    this.metrics
                        .jobs_abandoned_counter
                        .add(&Context::current(), 1, &[]);
                    return this.abandon_collect_job(datastore, collect_job_lease).await;
                }

                this.step_collect_job(datastore, collect_job_lease).await
            })
        }
    }
}

/// Computes the aggregate share over the provided batch unit aggregations.
/// The assumption is that all aggregation jobs contributing to those batch unit aggregations have
/// been driven to completion, and that the batch lifetime requirements have been validated for the
/// included batch units.
#[tracing::instrument(err)]
pub(crate) async fn compute_aggregate_share<const L: usize, A: vdaf::Aggregator<L>>(
    task: &Task,
    batch_unit_aggregations: &[BatchUnitAggregation<L, A>],
) -> Result<(A::AggregateShare, u64, ReportIdChecksum), Error>
where
    Vec<u8>: for<'a> From<&'a A::AggregateShare>,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
{
    // At the moment we construct an aggregate share (either handling AggregateShareReq in the
    // helper or driving a collect job in the leader), there could be some incomplete aggregation
    // jobs whose results not been accumulated into the batch unit aggregations we just queried from
    // the datastore, meaning we will aggregate over an incomplete view of data, which:
    //
    //  * reduces fidelity of the resulting aggregates,
    //  * could cause us to fail to meet the minimum batch size for the task,
    //  * or for particularly pathological timing, could cause us to aggregate a different set of
    //    reports than the leader did (though the checksum will detect this).
    //
    // There's not much the helper can do about this, because an aggregate job might be unfinished
    // because it's waiting on an aggregate sub-protocol message that is never coming because the
    // leader has abandoned that job. Thus the helper has no choice but to assume that any
    // unfinished aggregation jobs were intentionally abandoned by the leader (see issue #104 for
    // more discussion).
    //
    // On the leader side, we know/assume that we would not be stepping a collect job unless we had
    // verified that the constituent aggregation jobs were finished
    //
    // In either case, we go ahead and service the aggregate share request with whatever batch unit
    // aggregations are available now.
    let mut total_report_count = 0;
    let mut total_checksum = ReportIdChecksum::default();
    let mut total_aggregate_share: Option<A::AggregateShare> = None;

    for batch_unit_aggregation in batch_unit_aggregations {
        // §4.4.4.3: XOR this batch interval's checksum into the overall checksum
        total_checksum.combine(&batch_unit_aggregation.checksum);

        // §4.4.4.3: Sum all the report counts
        total_report_count += batch_unit_aggregation.report_count;

        match &mut total_aggregate_share {
            Some(share) => share.merge(&batch_unit_aggregation.aggregate_share)?,
            None => total_aggregate_share = Some(batch_unit_aggregation.aggregate_share.clone()),
        }
    }

    let total_aggregate_share = match total_aggregate_share {
        Some(share) => share,
        None => return Err(Error::InsufficientBatchSize(task.id, 0)),
    };

    // §4.6: refuse to service aggregate share requests if there are too few reports
    // included.
    if total_report_count < task.min_batch_size {
        return Err(Error::InsufficientBatchSize(task.id, total_report_count));
    }

    Ok((total_aggregate_share, total_report_count, total_checksum))
}

/// Check whether this collect interval has been included in enough collect jobs (for `task.role` ==
/// [`Role::Leader`]) or aggregate share jobs (for `task.role` == [`Role::Helper`]) to violate the
/// task's maximum batch lifetime, and that this collect interval does not partially overlap with
/// an already-observed collect interval.
pub(crate) async fn validate_batch_lifetime_for_collect<
    const L: usize,
    C: Clock,
    A: vdaf::Aggregator<L>,
>(
    tx: &Transaction<'_, C>,
    task: &Task,
    collect_interval: Interval,
) -> Result<(), datastore::Error>
where
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    // Check how many rows in the relevant table have an intersecting batch interval.
    // Each such row consumes one unit of batch lifetime (§4.6).
    let intersecting_intervals: Vec<_> = match task.role {
        Role::Leader => tx
            .find_collect_jobs_jobs_intersecting_interval::<L, A>(task.id, collect_interval)
            .await?
            .into_iter()
            .map(|job| job.batch_interval)
            .collect(),

        Role::Helper => tx
            .find_aggregate_share_jobs_intersecting_interval::<L, A>(task.id, collect_interval)
            .await?
            .into_iter()
            .map(|job| job.batch_interval)
            .collect(),

        _ => panic!("Unexpected task role {:?}", task.role),
    };

    // Check that all intersecting collect intervals are equal to this collect interval.
    if intersecting_intervals
        .iter()
        .any(|interval| interval != &collect_interval)
    {
        return Err(datastore::Error::User(
            Error::BatchInvalid(task.id, collect_interval).into(),
        ));
    }

    // Check that the batch lifetime is being consumed appropriately.
    let max_batch_lifetime: usize = task.max_batch_lifetime.try_into()?;
    if intersecting_intervals.len() == max_batch_lifetime {
        debug!(
            task_id = ?task.id, ?collect_interval,
            "Refusing aggregate share request because batch lifetime has been consumed"
        );
        return Err(datastore::Error::User(
            Error::BatchLifetimeExceeded(task.id).into(),
        ));
    }
    if intersecting_intervals.len() > max_batch_lifetime {
        error!(
            task_id = ?task.id, ?collect_interval,
            "Batch lifetime has been consumed more times than task allows"
        );

        // We return an internal error since this should be impossible.
        return Err(datastore::Error::User(
            Error::Internal("batch lifetime overconsumed".to_string()).into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        binary_utils::job_driver::JobDriver,
        datastore::{
            models::{
                AggregationJob, AggregationJobState, CollectJob, CollectJobState,
                ReportAggregation, ReportAggregationState,
            },
            test_util::ephemeral_datastore,
        },
        messages::TimeExt,
        task::VdafInstance,
    };
    use assert_matches::assert_matches;
    use http::{header::CONTENT_TYPE, StatusCode};
    use janus_core::{
        test_util::{
            dummy_vdaf::{AggregateShare, AggregationParam, OutputShare},
            install_test_trace_subscriber,
            runtime::TestRuntimeManager,
        },
        time::{MockClock, TimeExt as CoreTimeExt},
        Runtime,
    };
    use janus_messages::{
        Duration, HpkeCiphertext, HpkeConfigId, Interval, Report, ReportMetadata, Role,
    };
    use mockito::mock;
    use opentelemetry::global::meter;
    use rand::random;
    use std::str;
    use url::Url;

    async fn setup_collect_job_test_case(
        clock: MockClock,
        datastore: Arc<Datastore<MockClock>>,
        acquire_lease: bool,
    ) -> (
        Option<Lease<AcquiredCollectJob>>,
        CollectJob<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>,
    ) {
        let task_id = random();
        let mut task = Task::new_dummy(task_id, VdafInstance::Fake, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        let batch_interval = Interval::new(clock.now(), Duration::from_seconds(2000)).unwrap();
        let aggregation_param = AggregationParam(0);

        let collect_job = CollectJob::new(task_id, batch_interval, aggregation_param);

        let lease = datastore
            .run_tx(|tx| {
                let clock = clock.clone();
                let task = task.clone();
                let collect_job = collect_job.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(&collect_job)
                        .await?;

                    let aggregation_job_id = random();
                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        aggregation_param,
                        state: AggregationJobState::Finished,
                    })
                    .await?;

                    let report_metadata = ReportMetadata::new(
                        random(),
                        clock
                            .now()
                            .to_batch_unit_interval_start(task.min_batch_duration)
                            .unwrap(),
                        Vec::new(),
                    );
                    tx.put_client_report(&Report::new(
                        task_id,
                        report_metadata.clone(),
                        Vec::new(),
                        Vec::new(),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        time: *report_metadata.time(),
                        report_id: *report_metadata.report_id(),
                        ord: 0,
                        state: ReportAggregationState::Finished(OutputShare()),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        task_id,
                        unit_interval_start: clock.now(),
                        aggregation_param,
                        aggregate_share: AggregateShare(0),
                        report_count: 5,
                        checksum: ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                    })
                    .await?;
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        task_id,
                        unit_interval_start: clock.now().add(Duration::from_seconds(1000)).unwrap(),
                        aggregation_param,
                        aggregate_share: AggregateShare(0),
                        report_count: 5,
                        checksum: ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                    })
                    .await?;

                    if acquire_lease {
                        let lease = tx
                            .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                            .await?
                            .remove(0);
                        assert_eq!(task_id, lease.leased().task_id);
                        assert_eq!(collect_job.id, lease.leased().collect_job_id);
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

        let task_id = random();
        let mut task = Task::new_dummy(task_id, VdafInstance::Fake, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        let agg_auth_token = task.primary_aggregator_auth_token();
        let batch_interval = Interval::new(clock.now(), Duration::from_seconds(2000)).unwrap();
        let aggregation_param = AggregationParam(0);

        let (collect_job_id, lease) = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                let task = task.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    let collect_job = CollectJob::new(task_id, batch_interval, aggregation_param);
                    tx.put_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(&collect_job)
                        .await?;

                    let aggregation_job_id = random();
                    tx.put_aggregation_job(&AggregationJob::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        aggregation_param,
                        state: AggregationJobState::Finished,
                    })
                    .await?;

                    let report_metadata = ReportMetadata::new(
                        random(),
                        clock
                            .now()
                            .to_batch_unit_interval_start(task.min_batch_duration)
                            .unwrap(),
                        Vec::new(),
                    );
                    tx.put_client_report(&Report::new(
                        task_id,
                        report_metadata.clone(),
                        Vec::new(),
                        Vec::new(),
                    ))
                    .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        DUMMY_VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        time: *report_metadata.time(),
                        report_id: *report_metadata.report_id(),
                        ord: 0,
                        state: ReportAggregationState::Finished(OutputShare()),
                    })
                    .await?;

                    let lease = tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                        .await?
                        .remove(0);
                    assert_eq!(task_id, lease.leased().task_id);
                    assert_eq!(collect_job.id, lease.leased().collect_job_id);
                    Ok((collect_job.id, lease))
                })
            })
            .await
            .unwrap();

        let collect_job_driver = CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &meter("collect_job_driver"),
        );

        // No batch unit aggregations inserted yet
        let error = collect_job_driver
            .step_collect_job(ds.clone(), lease.clone())
            .await
            .unwrap_err();
        assert_matches!(error, Error::InsufficientBatchSize(error_task_id, 0) => {
            assert_eq!(task_id, error_task_id)
        });

        // Put some batch unit aggregations in the DB
        ds.run_tx(|tx| {
            let clock = clock.clone();
            Box::pin(async move {
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                    DUMMY_VERIFY_KEY_LENGTH,
                    dummy_vdaf::Vdaf,
                > {
                    task_id,
                    unit_interval_start: clock.now(),
                    aggregation_param,
                    aggregate_share: AggregateShare(0),
                    report_count: 5,
                    checksum: ReportIdChecksum::get_decoded(&[3; 32]).unwrap(),
                })
                .await?;

                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                    DUMMY_VERIFY_KEY_LENGTH,
                    dummy_vdaf::Vdaf,
                > {
                    task_id,
                    unit_interval_start: clock.now().add(Duration::from_seconds(1000)).unwrap(),
                    aggregation_param,
                    aggregate_share: AggregateShare(0),
                    report_count: 5,
                    checksum: ReportIdChecksum::get_decoded(&[2; 32]).unwrap(),
                })
                .await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        let leader_request = AggregateShareReq::new(
            task_id,
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
            .create();

        let error = collect_job_driver
            .step_collect_job(ds.clone(), lease.clone())
            .await
            .unwrap_err();
        assert_matches!(error, Error::Http(StatusCode::INTERNAL_SERVER_ERROR));

        mocked_failed_aggregate_share.assert();

        // Collect job in datastore should be unchanged.
        ds.run_tx(|tx| {
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(collect_job.state, CollectJobState::Start);
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
            .step_collect_job(ds.clone(), lease.clone())
            .await
            .unwrap();

        mocked_aggregate_share.assert();

        // Should now have recorded helper encrypted aggregate share, too.
        ds.run_tx(|tx| {
            let helper_aggregate_share = helper_response.encrypted_aggregate_share().clone();
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job_id)
                    .await
                    .unwrap()
                    .unwrap();

                assert_matches!(collect_job.state, CollectJobState::Finished{ encrypted_helper_aggregate_share, .. } => {
                    assert_eq!(encrypted_helper_aggregate_share, helper_aggregate_share);
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
                        .get_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(
                            collect_job.id,
                        )
                        .await?
                        .unwrap();

                    let leases = tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                        .await?;

                    Ok((abandoned_collect_job, leases))
                })
            })
            .await
            .unwrap();
        assert_eq!(
            abandoned_collect_job,
            CollectJob {
                state: CollectJobState::Abandoned,
                ..collect_job
            }
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
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::from_seconds(60),
            collect_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&ds),
                Duration::from_seconds(600),
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
                    tx.get_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job.id)
                        .await
                })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            collect_job_after,
            CollectJob {
                state: CollectJobState::Abandoned,
                ..collect_job
            },
        );
    }

    #[tokio::test]
    async fn delete_collect_job() {
        // Setup: insert a collect job into the datastore.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let (lease, mut collect_job) =
            setup_collect_job_test_case(clock, Arc::clone(&ds), true).await;

        // Delete the collect job
        collect_job.state = CollectJobState::Deleted;

        ds.run_tx(|tx| {
            let collect_job = collect_job.clone();
            Box::pin(async move {
                tx.update_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(&collect_job)
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
            .step_collect_job(ds.clone(), lease.unwrap().clone())
            .await
            .unwrap();

        mocked_aggregate_share.assert();

        // Verify: check that the collect job was abandoned, and that it can no longer be acquired.
        ds.run_tx(|tx| {
            let collect_job = collect_job.clone();
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<DUMMY_VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job.id)
                    .await
                    .unwrap()
                    .unwrap();

                assert_eq!(collect_job.state, CollectJobState::Deleted);

                let leases = tx
                    .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
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
