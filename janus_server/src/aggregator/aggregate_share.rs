//! Implements portions of collect sub-protocol for DAP leader and helper.

use super::Error;
use crate::{
    datastore::{
        self, models::AcquiredCollectJob, models::BatchUnitAggregation, Datastore, Transaction,
    },
    message::{AggregateShareReq, AggregateShareResp},
    task::Task,
    task::{VdafInstance, DAP_AUTH_HEADER},
};
use http::header::CONTENT_TYPE;
use janus::{
    message::{Interval, NonceChecksum, Role, TaskId},
    time::Clock,
};
use prio::{
    codec::{Decode, Encode},
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        Aggregatable,
    },
};
use std::{fmt::Debug, sync::Arc};
use tracing::{debug, error, log::warn};
use uuid::Uuid;

/// Drives a collect job.
#[derive(Debug)]
pub struct CollectJobDriver {
    http_client: reqwest::Client,
}

impl CollectJobDriver {
    /// Create a new [`CollectJobDriver`].
    pub fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
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
        acquired_collect_job: &AcquiredCollectJob,
    ) -> Result<(), Error> {
        match acquired_collect_job.vdaf {
            VdafInstance::Prio3Aes128Count => {
                self.step_collect_job_generic::<C, Prio3Aes128Count>(
                    datastore,
                    acquired_collect_job.task_id,
                    acquired_collect_job.collect_job_id,
                )
                .await
            }

            VdafInstance::Prio3Aes128Sum { .. } => {
                self.step_collect_job_generic::<C, Prio3Aes128Sum>(
                    datastore,
                    acquired_collect_job.task_id,
                    acquired_collect_job.collect_job_id,
                )
                .await
            }

            VdafInstance::Prio3Aes128Histogram { .. } => {
                self.step_collect_job_generic::<C, Prio3Aes128Histogram>(
                    datastore,
                    acquired_collect_job.task_id,
                    acquired_collect_job.collect_job_id,
                )
                .await
            }

            #[cfg(test)]
            VdafInstance::Fake => {
                self.step_collect_job_generic::<C, janus_test_util::dummy_vdaf::VdafWithAggregationParameter<u8>>(
                    datastore,
                    acquired_collect_job.task_id,
                    acquired_collect_job.collect_job_id,
                )
                .await
            }

            _ => panic!("VDAF {:?} is not yet supported", acquired_collect_job.vdaf),
        }
    }

    #[tracing::instrument(skip(self, datastore), err)]
    async fn step_collect_job_generic<C, A>(
        &self,
        datastore: Arc<Datastore<C>>,
        task_id: TaskId,
        collect_job_id: Uuid,
    ) -> Result<(), Error>
    where
        C: Clock,
        A: vdaf::Aggregator,
        A::AggregationParam: Send + Sync,
        A::AggregateShare: 'static + Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
        Vec<u8>: for<'a> From<&'a A::AggregateShare>,
        A::OutputShare: PartialEq + Eq + Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let (task, collect_job) = datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    // TODO: Consider fleshing out `AcquiredCollectJob` to include a `Task`,
                    // `A::AggregationParam`, etc. so that we don't have to do more DB queries here.
                    let task = tx.get_task(task_id).await?.ok_or_else(|| {
                        datastore::Error::User(Error::UnrecognizedTask(task_id).into())
                    })?;

                    let mut collect_job = tx
                        .get_collect_job::<A>(collect_job_id)
                        .await?
                        .ok_or_else(|| {
                            datastore::Error::User(
                                Error::UnrecognizedCollectJob(collect_job_id).into(),
                            )
                        })?;

                    if collect_job.leader_aggregate_share.is_some() {
                        return Ok((task, collect_job));
                    }

                    let batch_unit_aggregations = tx
                        .get_batch_unit_aggregations_for_task_in_interval::<A>(
                            task.id,
                            collect_job.batch_interval,
                            &collect_job.aggregation_param,
                        )
                        .await?;

                    let (leader_aggregate_share, report_count, checksum) =
                        compute_aggregate_share::<A>(&task, &batch_unit_aggregations)
                            .await
                            .map_err(|e| datastore::Error::User(e.into()))?;

                    collect_job.leader_aggregate_share = Some(leader_aggregate_share);
                    collect_job.report_count = Some(report_count);
                    collect_job.checksum = Some(checksum);

                    Ok((task, collect_job))
                })
            })
            .await?;

        if collect_job.helper_aggregate_share.is_some() {
            warn!("collect job being stepped already has a computed helper share");
            assert!(
                collect_job.leader_aggregate_share.is_some()
                    && collect_job.report_count.is_some()
                    && collect_job.checksum.is_some(),
                "collect job results in inconsistent state: {:?}",
                collect_job
            );
            return Ok(());
        }

        // Send an aggregate share request to the helper.
        let req = AggregateShareReq {
            task_id: task.id,
            batch_interval: collect_job.batch_interval,
            aggregation_param: collect_job.aggregation_param.get_encoded(),
            report_count: collect_job.report_count.unwrap(),
            checksum: collect_job.checksum.unwrap(),
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

        // Store the helper aggregate share in the datastore so that a later request to a collect
        // job URI can serve it up.
        let resp = AggregateShareResp::get_decoded(&response.bytes().await?)?;

        datastore
            .run_tx(|tx| {
                let helper_aggregate_share = resp.encrypted_aggregate_share.clone();
                let collect_job = collect_job.clone();
                Box::pin(async move {
                    tx.update_collect_job::<A>(
                        collect_job_id,
                        &collect_job.leader_aggregate_share.unwrap(),
                        collect_job.report_count.unwrap(),
                        collect_job.checksum.unwrap(),
                        &helper_aggregate_share,
                    )
                    .await?;

                    tx.release_collect_job(task.id, collect_job_id).await
                })
            })
            .await?;

        Ok(())
    }
}

/// Computes the aggregate share over the provided batch unit aggregations.
/// The assumption is that all aggregation jobs contributing to those batch unit aggregations have
/// been driven to completion, and that the batch lifetime requirements have been validated for the
/// included batch units.
#[tracing::instrument(err)]
pub(crate) async fn compute_aggregate_share<A>(
    task: &Task,
    batch_unit_aggregations: &[BatchUnitAggregation<A>],
) -> Result<(A::AggregateShare, u64, NonceChecksum), Error>
where
    A: vdaf::Aggregator,
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

/// Check whether any member of `batch_unit_aggregations` has been included in enough collect
/// jobs (for `task.role` == [`Role::Leader`]) or aggregate share jobs (for `task.role` ==
/// [`Role::Helper`]) to violate the task's maximum batch lifetime.
pub(crate) async fn validate_batch_lifetime_for_unit_aggregations<A, C>(
    tx: &Transaction<'_, C>,
    task: &Task,
    batch_unit_aggregations: &[BatchUnitAggregation<A>],
) -> Result<(), datastore::Error>
where
    A: vdaf::Aggregator,
    Vec<u8>: for<'a> From<&'a A::AggregateShare>,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: std::fmt::Display,
    C: Clock,
{
    // Check how many rows in the relevant table have a batch interval that includes each batch
    // unit. Each such row consumes one unit of batch lifetime (§4.6).
    //
    // We have to check each batch unit interval separately rather than checking how many times
    // aggregate_share_req.batch_interval overlaps with any row. Suppose we had:
    //
    //   * task.max_batch_lifetime = 2,
    //   * an AggregateShareReq.batch interval that spans two batch units,
    //   * and that each of those batch units has been collected once before.
    //
    // A further AggregateShareReq including either or both of the units is permissible, but
    // if we queried how many rows overlap with that interval, we would get 2 and refuse the
    // request. We must check the unit intervals individually to notice that each has enough
    // remaining lifetime to permit the share request.
    //
    // TODO: We believe this to be a correct implementation of currently specified batch
    // parameter validation, but we also know it to be inadequate. This should work for interop
    // experiments, but we should do better before we allow any real user data to be processed
    // (see issue #149).
    let intervals: Vec<_> = batch_unit_aggregations
        .iter()
        .map(|v| {
            Interval::new(v.unit_interval_start, task.min_batch_duration)
                .map_err(|e| datastore::Error::User(e.into()))
        })
        .collect::<Result<_, datastore::Error>>()?;

    let overlaps = tx
        .get_aggregate_share_job_counts_for_intervals(task.id, task.role, &intervals)
        .await?;

    for (unit_interval, consumed_batch_lifetime) in overlaps {
        if consumed_batch_lifetime == task.max_batch_lifetime {
            debug!(
                ?task.id, ?unit_interval,
                "refusing aggregate share request because lifetime for batch unit has been consumed"
            );
            return Err(datastore::Error::User(
                Error::BatchLifetimeExceeded(task.id).into(),
            ));
        }
        if consumed_batch_lifetime > task.max_batch_lifetime {
            error!(
                ?task.id, ?unit_interval,
                "batch unit lifetime has been consumed more times than task allows"
            );
            panic!("batch unit lifetime has already been consumed more times than task allows");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::{Crypter, Datastore},
        task::{test_util::new_dummy_task, VdafInstance},
        trace::test_util::install_test_trace_subscriber,
    };
    use assert_matches::assert_matches;
    use janus::message::{Duration, HpkeCiphertext, HpkeConfigId, Interval, Role, TaskId, Time};
    use janus_test_util::{
        dummy_vdaf::{AggregateShare, VdafWithAggregationParameter},
        MockClock,
    };
    use mockito::mock;
    use std::str;
    use url::Url;

    janus_test_util::define_ephemeral_datastore!();

    #[tokio::test]
    async fn drive_collect_job() {
        type FakeVdaf = VdafWithAggregationParameter<u8>;
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Fake, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.min_batch_duration = Duration::from_seconds(500);
        task.min_batch_size = 10;
        let agg_auth_token = task.primary_aggregator_auth_token();
        let batch_interval = Interval::new(
            Time::from_seconds_since_epoch(0),
            Duration::from_seconds(2000),
        )
        .unwrap();
        let aggregation_param = 0u8;

        let collect_job_id = ds
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move {
                    tx.put_task(&task).await?;

                    tx.put_collect_job(task_id, batch_interval, &aggregation_param.get_encoded())
                        .await
                })
            })
            .await
            .unwrap();

        let acquired_collect_job = AcquiredCollectJob {
            vdaf: VdafInstance::Fake,
            task_id,
            collect_job_id,
        };

        let collect_job_driver = CollectJobDriver {
            http_client: reqwest::Client::builder().build().unwrap(),
        };

        // No batch unit aggregations inserted yet
        let error = collect_job_driver
            .step_collect_job(ds.clone(), &acquired_collect_job)
            .await
            .unwrap_err();
        assert_matches!(error, Error::InsufficientBatchSize(0, error_task_id) => {
            assert_eq!(task_id, error_task_id)
        });

        // Put some batch unit aggregations in the DB
        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<FakeVdaf> {
                    task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(500),
                    aggregation_param,
                    aggregate_share: AggregateShare(),
                    report_count: 5,
                    checksum: NonceChecksum::get_decoded(&[3; 32]).unwrap(),
                })
                .await?;

                tx.put_batch_unit_aggregation(&BatchUnitAggregation::<FakeVdaf> {
                    task_id,
                    unit_interval_start: Time::from_seconds_since_epoch(1500),
                    aggregation_param,
                    aggregate_share: AggregateShare(),
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
            .step_collect_job(ds.clone(), &acquired_collect_job)
            .await
            .unwrap_err();

        mocked_failed_aggregate_share.assert();

        // Collect job in datastore should be unchanged.
        ds.run_tx(|tx| {
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<FakeVdaf>(collect_job_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(collect_job.leader_aggregate_share.is_none());
                assert!(collect_job.report_count.is_none());
                assert!(collect_job.checksum.is_none());
                assert!(collect_job.helper_aggregate_share.is_none());

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
            .step_collect_job(ds.clone(), &acquired_collect_job)
            .await
            .unwrap();

        mocked_aggregate_share.assert();

        // Should now have recorded helper encrypted aggregate share, too.
        ds.run_tx(|tx| {
            let helper_aggregate_share = helper_response.encrypted_aggregate_share.clone();
            Box::pin(async move {
                let collect_job = tx
                    .get_collect_job::<FakeVdaf>(collect_job_id)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(collect_job.leader_aggregate_share.is_some());
                assert_eq!(collect_job.report_count.unwrap(), 10);
                assert_eq!(
                    collect_job.checksum.unwrap(),
                    NonceChecksum::get_decoded(&[3 ^ 2; 32]).unwrap()
                );
                assert_eq!(
                    collect_job.helper_aggregate_share.unwrap(),
                    helper_aggregate_share
                );

                Ok(())
            })
        })
        .await
        .unwrap();

        // Drive collect job again. It should succeed without contacting the helper.
        collect_job_driver
            .step_collect_job(ds.clone(), &acquired_collect_job)
            .await
            .unwrap();
    }
}
