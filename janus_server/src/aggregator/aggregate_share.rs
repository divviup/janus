//! Implements portions of collect sub-protocol for DAP leader and helper.

use super::Error;
use crate::{
    datastore::{
        self,
        models::AcquiredCollectJob,
        models::{BatchUnitAggregation, CollectJobState, Lease},
        Datastore, Transaction,
    },
    message::{AggregateShareReq, AggregateShareResp},
    task::{Task, PRIO3_AES128_VERIFY_KEY_LENGTH},
    task::{VdafInstance, DAP_AUTH_HEADER},
};
use futures::{future::BoxFuture, try_join};
use http::header::CONTENT_TYPE;
#[cfg(test)]
use janus_core::test_util::dummy_vdaf;
use janus_core::{
    message::{Duration, Interval, NonceChecksum, Role},
    time::Clock,
};
use opentelemetry::metrics::{Counter, Meter};
use prio::{
    codec::{Decode, Encode},
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        Aggregatable,
    },
};
use std::{fmt::Debug, sync::Arc};
use tracing::{debug, error, warn};

/// Drives a collect job.
#[derive(Debug)]
pub struct CollectJobDriver {
    http_client: reqwest::Client,
    job_cancel_counter: Counter<u64>,
}

impl CollectJobDriver {
    /// Create a new [`CollectJobDriver`].
    pub fn new(http_client: reqwest::Client, meter: &Meter) -> Self {
        let job_cancel_counter = meter
            .u64_counter("janus_job_cancellations")
            .with_description("Count of cancelled jobs.")
            .init();

        Self {
            http_client,
            job_cancel_counter,
        }
    }

    /// Step the provided collect job, for which a lease should have been acquired (though this
    /// should be idempotent). If the collect job runs to completion, the leader share, helper
    /// share, report count and report nonce checksum will be written to the `collect_jobs` table,
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
                const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;
                self.step_collect_job_generic::<VERIFY_KEY_LENGTH, C, dummy_vdaf::Vdaf>(
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
        let (task, collect_job, batch_unit_aggregations) = datastore
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
            return Ok(());
        }

        let (leader_aggregate_share, report_count, checksum) =
            compute_aggregate_share::<L, A>(&task, &batch_unit_aggregations)
                .await
                .map_err(|e| datastore::Error::User(e.into()))?;

        // Send an aggregate share request to the helper.
        let req = AggregateShareReq {
            task_id: task.id,
            batch_interval: collect_job.batch_interval,
            aggregation_param: collect_job.aggregation_param.get_encoded(),
            report_count,
            checksum,
        };

        let response = self
            .http_client
            .post(
                task.aggregator_url(Role::Helper)?
                    .join("/aggregate_share")?,
            )
            .header(CONTENT_TYPE, AggregateShareReq::MEDIA_TYPE)
            .header(
                DAP_AUTH_HEADER,
                task.primary_aggregator_auth_token().as_bytes(),
            )
            .body(req.get_encoded())
            .send()
            .await?;
        let encrypted_helper_aggregate_share =
            AggregateShareResp::get_decoded(&response.bytes().await?)?.encrypted_aggregate_share;

        // Store the helper aggregate share in the datastore so that a later request to a collect
        // job URI can serve it up.
        let leader_aggregate_share = Arc::new(leader_aggregate_share);
        let encrypted_helper_aggregate_share = Arc::new(encrypted_helper_aggregate_share);
        let lease = Arc::new(lease);
        datastore
            .run_tx(|tx| {
                let leader_aggregate_share = Arc::clone(&leader_aggregate_share);
                let encrypted_helper_aggregate_share =
                    Arc::clone(&encrypted_helper_aggregate_share);
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    tx.update_collect_job::<L, A>(
                        collect_job_id,
                        &leader_aggregate_share,
                        &encrypted_helper_aggregate_share,
                    )
                    .await?;

                    tx.release_collect_job(&lease).await
                })
            })
            .await?;

        Ok(())
    }

    #[tracing::instrument(skip(self, datastore), err)]
    pub async fn cancel_collect_job<C: Clock>(
        &self,
        datastore: Arc<Datastore<C>>,
        lease: Lease<AcquiredCollectJob>,
    ) -> Result<(), Error> {
        let collect_job_id = lease.leased().collect_job_id;
        let lease = Arc::new(lease);
        datastore
            .run_tx(|tx| {
                let lease = Arc::clone(&lease);
                Box::pin(async move {
                    let cancel_future = tx.cancel_collect_job(collect_job_id);
                    let release_future = tx.release_collect_job(&lease);
                    try_join!(cancel_future, release_future)?;
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
                        "Canceling job due to too many failed attempts"
                    );
                    this.job_cancel_counter.add(1, &[]);
                    return this.cancel_collect_job(datastore, collect_job_lease).await;
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
) -> Result<(A::AggregateShare, u64, NonceChecksum), Error>
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
    let mut total_checksum = NonceChecksum::default();
    let mut total_aggregate_share: Option<A::AggregateShare> = None;

    for batch_unit_aggregation in batch_unit_aggregations {
        // §4.4.4.3: XOR this batch interval's checksum into the overall checksum
        total_checksum.combine(batch_unit_aggregation.checksum);

        // §4.4.4.3: Sum all the report counts
        total_report_count += batch_unit_aggregation.report_count;

        match &mut total_aggregate_share {
            Some(share) => share.merge(&batch_unit_aggregation.aggregate_share)?,
            None => total_aggregate_share = Some(batch_unit_aggregation.aggregate_share.clone()),
        }
    }

    let total_aggregate_share = match total_aggregate_share {
        Some(share) => share,
        None => return Err(Error::InsufficientBatchSize(0, task.id)),
    };

    // §4.6: refuse to service aggregate share requests if there are too few reports
    // included.
    if total_report_count < task.min_batch_size {
        return Err(Error::InsufficientBatchSize(total_report_count, task.id));
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
            Error::BatchInvalid(collect_interval, task.id).into(),
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
        message::AggregationJobId,
        task::{test_util::new_dummy_task, VdafInstance},
    };
    use assert_matches::assert_matches;
    use janus_core::{
        message::{Duration, HpkeCiphertext, HpkeConfigId, Interval, Nonce, Report, Role, TaskId},
        test_util::{
            dummy_vdaf::{AggregateShare, AggregationParam, OutputShare},
            install_test_trace_subscriber,
            runtime::TestRuntimeManager,
        },
        time::MockClock,
        Runtime,
    };
    use mockito::mock;
    use opentelemetry::global::meter;
    use std::str;
    use url::Url;

    #[tokio::test]
    async fn drive_collect_job() {
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
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

                    let collect_job_id = tx
                        .put_collect_job(task_id, batch_interval, &aggregation_param.get_encoded())
                        .await?;

                    let aggregation_job_id = AggregationJobId::random();
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param,
                            state: AggregationJobState::Finished,
                        },
                    )
                    .await?;

                    let nonce = Nonce::generate(&clock, task.min_batch_duration).unwrap();
                    tx.put_client_report(&Report::new(task_id, nonce, Vec::new(), Vec::new()))
                        .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce,
                        ord: 0,
                        state: ReportAggregationState::Finished(OutputShare()),
                    })
                    .await?;

                    let lease = tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                        .await?
                        .remove(0);
                    assert_eq!(task_id, lease.leased().task_id);
                    assert_eq!(collect_job_id, lease.leased().collect_job_id);
                    Ok((collect_job_id, lease))
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
        assert_matches!(error, Error::InsufficientBatchSize(0, error_task_id) => {
            assert_eq!(task_id, error_task_id)
        });

        // Put some batch unit aggregations in the DB
        ds.run_tx(|tx| {
            let clock = clock.clone();
            Box::pin(async move {
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                    VERIFY_KEY_LENGTH,
                    dummy_vdaf::Vdaf,
                > {
                    task_id,
                    unit_interval_start: clock.now(),
                    aggregation_param,
                    aggregate_share: AggregateShare(0),
                    report_count: 5,
                    checksum: NonceChecksum::get_decoded(&[3; 32]).unwrap(),
                })
                .await?;

                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                    VERIFY_KEY_LENGTH,
                    dummy_vdaf::Vdaf,
                > {
                    task_id,
                    unit_interval_start: clock.now().add(Duration::from_seconds(1000)).unwrap(),
                    aggregation_param,
                    aggregate_share: AggregateShare(0),
                    report_count: 5,
                    checksum: NonceChecksum::get_decoded(&[2; 32]).unwrap(),
                })
                .await?;

                Ok(())
            })
        })
        .await
        .unwrap();

        let leader_request = AggregateShareReq {
            task_id,
            batch_interval,
            aggregation_param: aggregation_param.get_encoded(),
            report_count: 10,
            checksum: NonceChecksum::get_decoded(&[3 ^ 2; 32]).unwrap(),
        };

        // Simulate helper failing to service the aggregate share request.
        let mocked_failed_aggregate_share = mock("POST", "/aggregate_share")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(CONTENT_TYPE.as_str(), AggregateShareReq::MEDIA_TYPE)
            .match_body(leader_request.get_encoded())
            .with_status(500)
            .create();

        collect_job_driver
            .step_collect_job(ds.clone(), lease.clone())
            .await
            .unwrap_err();

        mocked_failed_aggregate_share.assert();

        // Collect job in datastore should be unchanged.
        ds.run_tx(|tx| {
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job_id)
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
        let helper_response = AggregateShareResp {
            encrypted_aggregate_share: HpkeCiphertext::new(HpkeConfigId::from(100), vec![], vec![]),
        };

        let mocked_aggregate_share = mock("POST", "/aggregate_share")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(CONTENT_TYPE.as_str(), AggregateShareReq::MEDIA_TYPE)
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
            let helper_aggregate_share = helper_response.encrypted_aggregate_share.clone();
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job_id)
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
    async fn cancel_collect_job() {
        // Setup: insert a collect job into the datastore.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        let batch_interval = Interval::new(clock.now(), Duration::from_seconds(2000)).unwrap();
        let aggregation_param = AggregationParam(0);
        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let (collect_job_id, lease) = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                let task = task.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    let collect_job_id = tx
                        .put_collect_job(task_id, batch_interval, &aggregation_param.get_encoded())
                        .await?;

                    let aggregation_job_id = AggregationJobId::random();
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param,
                            state: AggregationJobState::Finished,
                        },
                    )
                    .await?;

                    let nonce = Nonce::generate(&clock, task.min_batch_duration).unwrap();
                    tx.put_client_report(&Report::new(task_id, nonce, Vec::new(), Vec::new()))
                        .await?;

                    tx.put_report_aggregation(&ReportAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        aggregation_job_id,
                        task_id,
                        nonce,
                        ord: 0,
                        state: ReportAggregationState::Finished(OutputShare()),
                    })
                    .await?;

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        task_id,
                        unit_interval_start: clock.now(),
                        aggregation_param,
                        aggregate_share: AggregateShare(0),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[3; 32]).unwrap(),
                    })
                    .await?;
                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        task_id,
                        unit_interval_start: clock.now().add(Duration::from_seconds(1000)).unwrap(),
                        aggregation_param,
                        aggregate_share: AggregateShare(0),
                        report_count: 5,
                        checksum: NonceChecksum::get_decoded(&[2; 32]).unwrap(),
                    })
                    .await?;

                    let lease = tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                        .await?
                        .remove(0);
                    assert_eq!(task_id, lease.leased().task_id);
                    assert_eq!(collect_job_id, lease.leased().collect_job_id);
                    Ok((collect_job_id, lease))
                })
            })
            .await
            .unwrap();

        let collect_job_driver = CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &meter("collect_job_driver"),
        );

        // Run: cancel the collect job.
        collect_job_driver
            .cancel_collect_job(Arc::clone(&ds), lease)
            .await
            .unwrap();

        // Verify: check that the collect job was abandoned, and that it can no longer be acquired.
        let (collect_job, leases) = ds
            .run_tx(|tx| {
                Box::pin(async move {
                    let collect_job = tx
                        .get_collect_job::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job_id)
                        .await?
                        .unwrap();

                    let leases = tx
                        .acquire_incomplete_collect_jobs(Duration::from_seconds(100), 1)
                        .await?;

                    Ok((collect_job, leases))
                })
            })
            .await
            .unwrap();
        assert_eq!(
            collect_job,
            CollectJob {
                collect_job_id,
                task_id,
                batch_interval,
                aggregation_param,
                state: CollectJobState::Abandoned,
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

        const VERIFY_KEY_LENGTH: usize = dummy_vdaf::Vdaf::VERIFY_KEY_LENGTH;

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        let agg_auth_token = task.primary_aggregator_auth_token();
        let batch_interval = Interval::new(clock.now(), Duration::from_seconds(2000)).unwrap();
        let aggregation_param = AggregationParam(0);

        // Set up the database with enough test fixtures to run a collect job.
        let collect_job_id = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                let task = task.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    let collect_job_id = tx
                        .put_collect_job(task_id, batch_interval, &aggregation_param.get_encoded())
                        .await?;

                    let aggregation_job_id = AggregationJobId::random();
                    tx.put_aggregation_job(
                        &AggregationJob::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param,
                            state: AggregationJobState::Finished,
                        },
                    )
                    .await?;

                    // We need to have some report aggregations present, so that our collect job
                    // can be picked up and the anti-replay check has something to check.
                    for i in 0..10 {
                        let nonce = Nonce::generate(&clock, task.min_batch_duration).unwrap();
                        tx.put_client_report(&Report::new(task_id, nonce, vec![], vec![]))
                            .await?;
                        tx.put_report_aggregation(&ReportAggregation::<
                            VERIFY_KEY_LENGTH,
                            dummy_vdaf::Vdaf,
                        > {
                            aggregation_job_id,
                            task_id,
                            nonce,
                            ord: i,
                            state: ReportAggregationState::Finished(OutputShare()),
                        })
                        .await?;
                    }

                    tx.put_batch_unit_aggregation(&BatchUnitAggregation::<
                        VERIFY_KEY_LENGTH,
                        dummy_vdaf::Vdaf,
                    > {
                        task_id,
                        unit_interval_start: clock.now(),
                        aggregation_param,
                        aggregate_share: AggregateShare(0),
                        report_count: 10,
                        checksum: NonceChecksum::get_decoded(&[0xff; 32]).unwrap(),
                    })
                    .await?;

                    Ok(collect_job_id)
                })
            })
            .await
            .unwrap();

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
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(CONTENT_TYPE.as_str(), AggregateShareReq::MEDIA_TYPE)
            .with_status(500)
            .expect(3)
            .create();
        // Set up an extra response that should never be used, to make sure the job driver doesn't
        // make more requests than we expect. If there were no remaining mocks, mockito would have
        // respond with a fallback error response instead.
        let no_more_requests_mock = mock("POST", "/aggregate_share")
            .match_header(
                "DAP-Auth-Token",
                str::from_utf8(agg_auth_token.as_bytes()).unwrap(),
            )
            .match_header(CONTENT_TYPE.as_str(), AggregateShareReq::MEDIA_TYPE)
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
                Box::pin(async move {
                    tx.get_collect_job::<VERIFY_KEY_LENGTH, dummy_vdaf::Vdaf>(collect_job_id)
                        .await
                })
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            collect_job_after,
            CollectJob {
                collect_job_id,
                task_id,
                batch_interval,
                aggregation_param,
                state: CollectJobState::Abandoned,
            },
        );
    }
}
