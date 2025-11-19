//! Database accessors for leased jobs.

use crate::datastore::{
    AsyncAggregator, Error, RowExt, Transaction,
    models::{AcquiredAggregationJob, AcquiredCollectionJob, LeaseToken},
    task,
};
use chrono::NaiveDateTime;
use janus_core::{
    time::{Clock, TimeExt},
    vdaf::VdafInstance,
};
use janus_messages::{
    AggregationJobId, CollectionJobId, TaskId, TimePrecision, batch_mode::BatchMode,
};
use postgres_types::{Json, Timestamp};
use prio::codec::Decode;
use std::fmt::Debug;
use tokio_postgres::Row;

impl<C: Clock> Transaction<'_, C> {
    /// Return the lease on a collection job for the provided ID, or `None` if no such collection
    /// job exists.
    ///
    /// # Discussion
    ///
    /// Unlike `acquire_incomplete_collection_jobs`, this method does not acquire a lease, but
    /// merely constructs a representation of the lease. Holding the returned value will not prevent
    /// another caller from acquiring the lease and stepping the job.
    pub async fn get_collection_job_lease<
        const SEED_SIZE: usize,
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        collection_job_id: &CollectionJobId,
    ) -> Result<Option<MaybeLease<AcquiredCollectionJob>>, Error> {
        let task_info = match self.task_info_for(task_id).await? {
            Some(task_info) => task_info,
            None => return Ok(None),
        };
        let now = self.clock.now().as_naive_date_time()?;

        let stmt = self
            .prepare_cached(
                r#"-- get_collection_job_lease
SELECT
    collection_jobs.id, collection_jobs.collection_job_id, collection_jobs.batch_identifier,
    collection_jobs.aggregation_param, collection_jobs.lease_expiry, collection_jobs.lease_token,
    collection_jobs.lease_attempts, collection_jobs.step_attempts, tasks.task_id, tasks.batch_mode,
    tasks.vdaf, tasks.time_precision
FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
WHERE collection_jobs.task_id = $1
    AND collection_jobs.collection_job_id = $2
    AND COALESCE(
        LOWER(batch_interval),
        (SELECT MAX(UPPER(ba.client_timestamp_interval))
            FROM batch_aggregations ba
            WHERE ba.task_id = collection_jobs.task_id
                AND ba.batch_identifier = collection_jobs.batch_identifier
                AND ba.aggregation_param = collection_jobs.aggregation_param),
        '-infinity'::TIMESTAMP)
        >= COALESCE(
            $3::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL,
            '-infinity'::TIMESTAMP
        )"#,
            )
            .await?;

        self.query_opt(
            &stmt,
            &[
                /* task ID */ &task_info.pkey,
                /* collection_job_id*/ &collection_job_id.as_ref(),
                /* now */ &now,
            ],
        )
        .await?
        .map(|row| maybe_leased_collection_job_from_row(&row))
        .transpose()
    }

    /// Return the leases on collection jobs for the provided task ID.
    ///
    /// # Discussion
    ///
    /// Unlike `acquire_incomplete_collection_jobs`, this method does not acquire leases, but
    /// merely constructs representations of leases. Holding the returned value will not prevent
    /// another caller from acquiring the leases and stepping the jobs.
    pub async fn get_collection_job_leases_by_task<
        const SEED_SIZE: usize,
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<MaybeLease<AcquiredCollectionJob>>, Error> {
        let task_info = match self.task_info_for(task_id).await? {
            Some(task_info) => task_info,
            None => return Ok(Vec::new()),
        };
        let now = self.clock.now().as_naive_date_time()?;

        let stmt = self
            .prepare_cached(
                r#"-- get_collection_job_leases_by_task
SELECT
    collection_jobs.id, collection_jobs.collection_job_id, collection_jobs.batch_identifier,
    collection_jobs.aggregation_param, collection_jobs.lease_expiry, collection_jobs.lease_token,
    collection_jobs.lease_attempts, collection_jobs.step_attempts, tasks.task_id, tasks.batch_mode,
    tasks.vdaf, tasks.time_precision
FROM collection_jobs JOIN tasks ON tasks.id = collection_jobs.task_id
WHERE collection_jobs.task_id = $1
    AND COALESCE(
        LOWER(batch_interval),
        (SELECT MAX(UPPER(ba.client_timestamp_interval))
            FROM batch_aggregations ba
            WHERE ba.task_id = collection_jobs.task_id
                AND ba.batch_identifier = collection_jobs.batch_identifier
                AND ba.aggregation_param = collection_jobs.aggregation_param),
        '-infinity'::TIMESTAMP)
        >= COALESCE(
            $2::TIMESTAMP - tasks.report_expiry_age * '1 second'::INTERVAL,
            '-infinity'::TIMESTAMP
        )"#,
            )
            .await?;

        self.query(&stmt, &[/* task ID */ &task_info.pkey, /* now */ &now])
            .await?
            .iter()
            .map(maybe_leased_collection_job_from_row)
            .collect()
    }

    /// Return the lease on an aggregation job for the provided ID, or `None` if no such aggregation
    /// job exists.
    ///
    /// # Discussion
    ///
    /// Unlike `acquire_incomplete_aggregation_jobs`, this method does not acquire a lease, but
    /// merely constructs a representation of the lease. Holding the returned value will not prevent
    /// another caller from acquiring the lease and stepping the job.
    pub async fn get_aggregation_job_lease<
        const SEED_SIZE: usize,
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
        aggregation_job_id: &AggregationJobId,
    ) -> Result<Option<MaybeLease<AcquiredAggregationJob>>, Error> {
        let task_info = match self.task_info_for(task_id).await? {
            Some(task_info) => task_info,
            None => return Ok(None),
        };

        let stmt = self
            .prepare_cached(
                r#"-- get_aggregation_job_lease
SELECT
    aggregation_jobs.id, aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_expiry,
    aggregation_jobs.lease_token, aggregation_jobs.lease_attempts,  tasks.batch_mode, tasks.vdaf,
    tasks.task_id
FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
WHERE aggregation_jobs.task_id = $1
    AND aggregation_jobs.aggregation_job_id = $2
    AND UPPER(aggregation_jobs.client_timestamp_interval) >= $3"#,
            )
            .await?;

        self.query_opt(
            &stmt,
            &[
                /* task ID */ &task_info.pkey,
                /* aggregation_job_id*/ &aggregation_job_id.as_ref(),
                /* threshold */
                &task_info.report_expiry_threshold(&self.clock.now().as_naive_date_time()?)?,
            ],
        )
        .await?
        .map(|row| maybe_leased_aggregation_job_from_row(&row))
        .transpose()
    }

    /// Return the leases on aggregation jobs for the provided task ID.
    ///
    /// # Discussion
    ///
    /// Unlike `acquire_incomplete_aggregation_jobs`, this method does not acquire leases, but
    /// merely constructs representations of leases. Holding the returned value will not prevent
    /// another caller from acquiring the leases and stepping the jobs.
    pub async fn get_aggregation_job_leases_by_task<
        const SEED_SIZE: usize,
        B: BatchMode,
        A: AsyncAggregator<SEED_SIZE>,
    >(
        &self,
        task_id: &TaskId,
    ) -> Result<Vec<MaybeLease<AcquiredAggregationJob>>, Error> {
        let task_info = match self.task_info_for(task_id).await? {
            Some(task_info) => task_info,
            None => return Ok(Vec::new()),
        };

        let stmt = self
            .prepare_cached(
                r#"-- get_aggregation_job_lease
SELECT
    aggregation_jobs.id, aggregation_jobs.aggregation_job_id, aggregation_jobs.lease_expiry,
    aggregation_jobs.lease_token, aggregation_jobs.lease_attempts,  tasks.batch_mode, tasks.vdaf,
    tasks.task_id
FROM aggregation_jobs JOIN tasks ON tasks.id = aggregation_jobs.task_id
WHERE aggregation_jobs.task_id = $1
    AND UPPER(aggregation_jobs.client_timestamp_interval) >= $2"#,
            )
            .await?;

        self.query(
            &stmt,
            &[
                /* task ID */ &task_info.pkey,
                /* threshold */
                &task_info.report_expiry_threshold(&self.clock.now().as_naive_date_time()?)?,
            ],
        )
        .await?
        .iter()
        .map(maybe_leased_aggregation_job_from_row)
        .collect()
    }
}

/// A representation of a lease on a job. Unlike a
/// `janus_aggregator::core::datastore::models::Lease`, this does not constitute a held lease on a
/// job. In fact, the job might not be leased at all, in which case the `lease_token` and
/// `lease_expiry_time` fields are `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaybeLease<T> {
    leased: T,
    pub lease_expiry_time: Timestamp<NaiveDateTime>,
    pub lease_token: Option<LeaseToken>,
    pub lease_attempts: usize,
}

impl<T> MaybeLease<T> {
    pub fn leased(&self) -> &T {
        &self.leased
    }
}

fn maybe_leased_collection_job_from_row(
    row: &Row,
) -> Result<MaybeLease<AcquiredCollectionJob>, Error> {
    let lease_expiry_time = row.try_get("lease_expiry")?;
    let lease_token = row.get_nullable_bytea_and_convert::<LeaseToken>("lease_token")?;
    let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;

    Ok(MaybeLease {
        leased: acquired_collection_job_from_row(row)?,
        lease_expiry_time,
        lease_token,
        lease_attempts,
    })
}

pub(crate) fn acquired_collection_job_from_row(row: &Row) -> Result<AcquiredCollectionJob, Error> {
    let task_id = TaskId::get_decoded(row.get("task_id"))?;
    let collection_job_id = row.get_bytea_and_convert::<CollectionJobId>("collection_job_id")?;
    let query_type = row.try_get::<_, Json<task::BatchMode>>("batch_mode")?.0;
    let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
    let time_precision = TimePrecision::from_seconds(row.get_bigint_and_convert("time_precision")?);
    let encoded_batch_identifier = row.get("batch_identifier");
    let encoded_aggregation_param = row.get("aggregation_param");
    let step_attempts = row.get_bigint_and_convert("step_attempts")?;

    Ok(AcquiredCollectionJob::new(
        task_id,
        collection_job_id,
        query_type,
        vdaf,
        time_precision,
        encoded_batch_identifier,
        encoded_aggregation_param,
        step_attempts,
    ))
}

fn maybe_leased_aggregation_job_from_row(
    row: &Row,
) -> Result<MaybeLease<AcquiredAggregationJob>, Error> {
    let lease_expiry_time = row.try_get("lease_expiry")?;
    let lease_token = row.get_nullable_bytea_and_convert::<LeaseToken>("lease_token")?;
    let lease_attempts = row.get_bigint_and_convert("lease_attempts")?;

    Ok(MaybeLease {
        leased: acquired_aggregation_job_from_row(row)?,
        lease_expiry_time,
        lease_token,
        lease_attempts,
    })
}

pub(crate) fn acquired_aggregation_job_from_row(
    row: &Row,
) -> Result<AcquiredAggregationJob, Error> {
    let task_id = TaskId::get_decoded(row.get("task_id"))?;
    let aggregation_job_id = row.get_bytea_and_convert::<AggregationJobId>("aggregation_job_id")?;
    let query_type = row.try_get::<_, Json<task::BatchMode>>("batch_mode")?.0;
    let vdaf = row.try_get::<_, Json<VdafInstance>>("vdaf")?.0;
    Ok(AcquiredAggregationJob::new(
        task_id,
        aggregation_job_id,
        query_type,
        vdaf,
    ))
}
