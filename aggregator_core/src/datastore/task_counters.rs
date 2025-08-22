use crate::datastore::{Error, RowExt, Transaction, check_single_row_mutation};
use janus_core::time::Clock;
use janus_messages::{ReportError, TaskId};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::Level;

/// Per-task counts of uploaded reports and upload attempts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(from = "TaskUploadCounterInner", into = "TaskUploadCounterInner")]
pub struct TaskUploadCounter {
    inner: Arc<Mutex<TaskUploadCounterInner>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "TaskUploadCounter")]
struct TaskUploadCounterInner {
    /// Reports that fell into a time interval that had already been collected.
    interval_collected: u64,
    /// Reports that could not be decoded.
    report_decode_failure: u64,
    /// Reports that could not be decrypted.
    report_decrypt_failure: u64,
    /// Reports that contained a timestamp too far in the past.
    report_expired: u64,
    /// Reports that were encrypted with an old or unknown HPKE key.
    report_outdated_key: u64,
    /// Reports that were successfully uploaded.
    report_success: u64,
    /// Reports that contain a timestamp too far in the future.
    report_too_early: u64,
    /// Reports that were submitted to the task before the task's start time.
    task_not_started: u64,
    /// Reports that were submitted to the task after the task's end time.
    task_ended: u64,
    /// Reports that contained a duplicate extension.
    duplicate_extension: u64,
}

impl From<TaskUploadCounterInner> for TaskUploadCounter {
    fn from(value: TaskUploadCounterInner) -> Self {
        Self {
            inner: Arc::new(Mutex::new(value)),
        }
    }
}

impl From<TaskUploadCounter> for TaskUploadCounterInner {
    fn from(value: TaskUploadCounter) -> Self {
        *value.inner.lock().unwrap()
    }
}

impl PartialEq for TaskUploadCounter {
    fn eq(&self, other: &Self) -> bool {
        self.inner.lock().unwrap().eq(&other.inner.lock().unwrap())
    }
}

impl Eq for TaskUploadCounter {}

impl TaskUploadCounter {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_values(
        interval_collected: u64,
        report_decode_failure: u64,
        report_decrypt_failure: u64,
        report_expired: u64,
        report_outdated_key: u64,
        report_success: u64,
        report_too_early: u64,
        task_not_started: u64,
        task_ended: u64,
        duplicate_extension: u64,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TaskUploadCounterInner {
                interval_collected,
                report_decode_failure,
                report_decrypt_failure,
                report_expired,
                report_outdated_key,
                report_success,
                report_too_early,
                task_not_started,
                task_ended,
                duplicate_extension,
            })),
        }
    }

    /// Load counters for the specified task from the datastore and construct a
    /// [`TaskUploadCounter`]. This is aggregated across all shards. Returns `None` if the task
    /// doesn't exist.
    #[tracing::instrument(skip(tx), err(level = Level::DEBUG))]
    pub async fn load<'a, C: Clock>(
        tx: &Transaction<'a, C>,
        task_id: &TaskId,
    ) -> Result<Option<Self>, Error> {
        let stmt = tx
            .prepare_cached(
                "-- get_task_upload_counter()
SELECT
    tasks.id,
    COALESCE(SUM(interval_collected)::BIGINT, 0) AS interval_collected,
    COALESCE(SUM(report_decode_failure)::BIGINT, 0) AS report_decode_failure,
    COALESCE(SUM(report_decrypt_failure)::BIGINT, 0) AS report_decrypt_failure,
    COALESCE(SUM(report_expired)::BIGINT, 0) AS report_expired,
    COALESCE(SUM(report_outdated_key)::BIGINT, 0) AS report_outdated_key,
    COALESCE(SUM(report_success)::BIGINT, 0) AS report_success,
    COALESCE(SUM(report_too_early)::BIGINT, 0) AS report_too_early,
    COALESCE(SUM(task_not_started)::BIGINT, 0) AS task_not_started,
    COALESCE(SUM(task_ended)::BIGINT, 0) AS task_ended,
    COALESCE(SUM(duplicate_extension)::BIGINT, 0) AS duplicate_extension
FROM task_upload_counters
RIGHT JOIN tasks on tasks.id = task_upload_counters.task_id
WHERE tasks.task_id = $1
GROUP BY tasks.id",
            )
            .await?;

        tx.query_opt(&stmt, &[task_id.as_ref()])
            .await?
            .map(|row| {
                Ok(Self::new_with_values(
                    row.get_bigint_and_convert("interval_collected")?,
                    row.get_bigint_and_convert("report_decode_failure")?,
                    row.get_bigint_and_convert("report_decrypt_failure")?,
                    row.get_bigint_and_convert("report_expired")?,
                    row.get_bigint_and_convert("report_outdated_key")?,
                    row.get_bigint_and_convert("report_success")?,
                    row.get_bigint_and_convert("report_too_early")?,
                    row.get_bigint_and_convert("task_not_started")?,
                    row.get_bigint_and_convert("task_ended")?,
                    row.get_bigint_and_convert("duplicate_extension")?,
                ))
            })
            .transpose()
    }

    /// Add the values in this counter to the counts persisted for the given [`TaskId`]. This is
    /// sharded, requiring an `ord` parameter to determine which shard to add to. `ord` should be
    /// randomly generated by the caller.
    #[tracing::instrument(skip(tx), err(level = Level::DEBUG))]
    pub async fn flush<'a, C: Clock>(
        self,
        task_id: &TaskId,
        tx: &Transaction<'a, C>,
        ord: u64,
    ) -> Result<(), Error> {
        // Copy the inner counter values so we don't have to hold a sync Mutex across await points
        let inner = *self.inner.lock().unwrap();

        let stmt = "-- increment_task_upload_counter()
INSERT INTO task_upload_counters (
    task_id, ord, interval_collected, report_decode_failure,
    report_decrypt_failure, report_expired, report_outdated_key, report_success, report_too_early,
    task_not_started, task_ended, duplicate_extension
)
VALUES ((SELECT id FROM tasks WHERE task_id = $1), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (task_id, ord) DO UPDATE SET
    interval_collected = task_upload_counters.interval_collected + $3,
    report_decode_failure = task_upload_counters.report_decode_failure + $4,
    report_decrypt_failure = task_upload_counters.report_decrypt_failure + $5,
    report_expired = task_upload_counters.report_expired + $6,
    report_outdated_key = task_upload_counters.report_outdated_key + $7,
    report_success = task_upload_counters.report_success + $8,
    report_too_early = task_upload_counters.report_too_early + $9,
    task_not_started = task_upload_counters.task_not_started + $10,
    task_ended = task_upload_counters.task_ended + $11,
    duplicate_extension = task_upload_counters.duplicate_extension + $12";

        let stmt = tx.prepare_cached(stmt).await?;
        check_single_row_mutation(
            tx.execute(
                &stmt,
                &[
                    task_id.as_ref(),
                    &i64::try_from(ord)?,
                    &i64::try_from(inner.interval_collected)?,
                    &i64::try_from(inner.report_decode_failure)?,
                    &i64::try_from(inner.report_decrypt_failure)?,
                    &i64::try_from(inner.report_expired)?,
                    &i64::try_from(inner.report_outdated_key)?,
                    &i64::try_from(inner.report_success)?,
                    &i64::try_from(inner.report_too_early)?,
                    &i64::try_from(inner.task_not_started)?,
                    &i64::try_from(inner.task_ended)?,
                    &i64::try_from(inner.duplicate_extension)?,
                ],
            )
            .await?,
        )
    }

    pub fn increment_interval_collected(&self) {
        self.inner.lock().unwrap().interval_collected += 1
    }

    pub fn increment_report_decode_failure(&self) {
        self.inner.lock().unwrap().report_decode_failure += 1
    }

    pub fn increment_report_decrypt_failure(&self) {
        self.inner.lock().unwrap().report_decrypt_failure += 1
    }

    pub fn increment_report_expired(&self) {
        self.inner.lock().unwrap().report_expired += 1
    }

    pub fn increment_report_outdated_key(&self) {
        self.inner.lock().unwrap().report_outdated_key += 1
    }

    pub fn increment_report_success(&self) {
        self.inner.lock().unwrap().report_success += 1
    }

    pub fn increment_report_too_early(&self) {
        self.inner.lock().unwrap().report_too_early += 1
    }

    pub fn increment_task_not_started(&self) {
        self.inner.lock().unwrap().task_not_started += 1
    }

    pub fn increment_task_ended(&self) {
        self.inner.lock().unwrap().task_ended += 1
    }

    pub fn increment_duplicate_extension(&self) {
        self.inner.lock().unwrap().duplicate_extension += 1
    }

    pub fn interval_collected(&self) -> u64 {
        self.inner.lock().unwrap().interval_collected
    }

    pub fn report_decode_failure(&self) -> u64 {
        self.inner.lock().unwrap().report_decode_failure
    }

    pub fn report_decrypt_failure(&self) -> u64 {
        self.inner.lock().unwrap().report_decrypt_failure
    }

    pub fn report_expired(&self) -> u64 {
        self.inner.lock().unwrap().report_expired
    }

    pub fn report_outdated_key(&self) -> u64 {
        self.inner.lock().unwrap().report_outdated_key
    }

    pub fn report_success(&self) -> u64 {
        self.inner.lock().unwrap().report_success
    }

    pub fn report_too_early(&self) -> u64 {
        self.inner.lock().unwrap().report_too_early
    }

    pub fn task_not_started(&self) -> u64 {
        self.inner.lock().unwrap().task_not_started
    }

    pub fn task_ended(&self) -> u64 {
        self.inner.lock().unwrap().task_ended
    }

    pub fn duplicate_extension(&self) -> u64 {
        self.inner.lock().unwrap().duplicate_extension
    }
}

/// Per-task counts of aggregated reports.
///
/// The intended scope of this structure is a single operation, e.g., a single step of a single
/// aggregation job. What that means is:
///   - The counter values in this structure will not represent the current totals for the task, but
///     rather just the contribution that the particular operation is making to the task total;
///   - Callers must flush the counter values to the datastore by calling
///     `Transaction::increment_task_aggregation_counter`. Callers must avoid double counting: any
///     operation's counters should only be flushed to datastore once.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(
    from = "TaskAggregationCounterInner",
    into = "TaskAggregationCounterInner"
)]
pub struct TaskAggregationCounter {
    inner: Arc<Mutex<TaskAggregationCounterInner>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename = "TaskAggregationCounter")]
pub struct TaskAggregationCounterInner {
    /// The number of successfully-aggregated reports.
    success: u64,

    /// The number of reports rejected due to duplicate extensions.
    duplicate_extension: u64,
    /// The number of reports rejected due to failure to encode the public share.
    public_share_encode_failure: u64,
    /// The number of reports rejected due to the batch being collected.
    batch_collected: u64,
    /// The number of reports rejected due to the report replay.
    report_replayed: u64,
    /// The number of reports rejected due to the leader dropping the report.
    report_dropped: u64,
    /// The number of reports rejected due to unknown HPKE config ID.
    hpke_unknown_config_id: u64,
    /// The number of reports rejected due to HPKE decryption failure.
    hpke_decrypt_failure: u64,
    /// The number of reports rejected due to VDAF preparation error.
    vdaf_prep_error: u64,
    /// The number of reports rejected due to the task not having started yet.
    task_not_started: u64,
    /// The number of reports rejected due to task expiration.
    task_expired: u64,
    /// The number of reports rejected due to an invalid message.
    invalid_message: u64,
    /// The number of reports rejected due to a report arriving too early.
    report_too_early: u64,

    /// The number of reports rejected by the helper due to the batch being collected.
    helper_batch_collected: u64,
    /// The number of reports rejected by the helper due to the report replay.
    helper_report_replayed: u64,
    /// The number of reports rejected by the helper due to the leader dropping the report.
    helper_report_dropped: u64,
    /// The number of reports rejected by the helper due to unknown HPKE config ID.
    helper_hpke_unknown_config_id: u64,
    /// The number of reports rejected by the helper due to HPKE decryption failure.
    helper_hpke_decrypt_failure: u64,
    /// The number of reports rejected by the helper due to VDAF preparation error.
    helper_vdaf_prep_error: u64,
    /// The number of reports rejected by the helper due to the task not having started yet.
    helper_task_not_started: u64,
    /// The number of reports rejected by the helper due to task expiration.
    helper_task_expired: u64,
    /// The number of reports rejected by the helper due to an invalid message.
    helper_invalid_message: u64,
    /// The number of reports rejected by the helper due to a report arriving too early.
    helper_report_too_early: u64,
}

impl From<TaskAggregationCounterInner> for TaskAggregationCounter {
    fn from(value: TaskAggregationCounterInner) -> Self {
        Self {
            inner: Arc::new(Mutex::new(value)),
        }
    }
}

impl From<TaskAggregationCounter> for TaskAggregationCounterInner {
    fn from(value: TaskAggregationCounter) -> Self {
        *value.inner.lock().unwrap()
    }
}

impl PartialEq for TaskAggregationCounter {
    fn eq(&self, other: &Self) -> bool {
        self.inner.lock().unwrap().eq(&other.inner.lock().unwrap())
    }
}

impl Eq for TaskAggregationCounter {}

impl TaskAggregationCounter {
    #[cfg(feature = "test-util")]
    pub fn with_success(self, value: u64) -> Self {
        self.inner.lock().unwrap().success = value;
        self
    }

    #[cfg(feature = "test-util")]
    pub fn with_helper_hpke_decrypt_failure(self, value: u64) -> Self {
        self.inner.lock().unwrap().helper_hpke_decrypt_failure = value;
        self
    }

    #[cfg(feature = "test-util")]
    pub fn with_helper_task_expired(self, value: u64) -> Self {
        self.inner.lock().unwrap().helper_task_expired = value;
        self
    }

    #[cfg(feature = "test-util")]
    pub fn with_vdaf_prep_error(self, value: u64) -> Self {
        self.inner.lock().unwrap().vdaf_prep_error = value;
        self
    }

    /// Construct a new `TaskAggregationCounter`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_values(
        success: u64,
        duplicate_extension: u64,
        public_share_encode_failure: u64,
        batch_collected: u64,
        report_replayed: u64,
        report_dropped: u64,
        hpke_unknown_config_id: u64,
        hpke_decrypt_failure: u64,
        vdaf_prep_error: u64,
        task_not_started: u64,
        task_expired: u64,
        invalid_message: u64,
        report_too_early: u64,
        helper_batch_collected: u64,
        helper_report_replayed: u64,
        helper_report_dropped: u64,
        helper_hpke_unknown_config_id: u64,
        helper_hpke_decrypt_failure: u64,
        helper_vdaf_prep_error: u64,
        helper_task_not_started: u64,
        helper_task_expired: u64,
        helper_invalid_message: u64,
        helper_report_too_early: u64,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TaskAggregationCounterInner {
                success,
                duplicate_extension,
                public_share_encode_failure,
                batch_collected,
                report_replayed,
                report_dropped,
                hpke_unknown_config_id,
                hpke_decrypt_failure,
                vdaf_prep_error,
                task_not_started,
                task_expired,
                invalid_message,
                report_too_early,
                helper_batch_collected,
                helper_report_replayed,
                helper_report_dropped,
                helper_hpke_unknown_config_id,
                helper_hpke_decrypt_failure,
                helper_vdaf_prep_error,
                helper_task_not_started,
                helper_task_expired,
                helper_invalid_message,
                helper_report_too_early,
            })),
        }
    }

    /// Load counters for the specified task from the datastore and construct a
    /// [`TaskAggregationCounter`]. This is aggregated across all shards. Returns `None` if the task
    /// doesn't exist.
    #[tracing::instrument(skip(tx), err(level = Level::DEBUG))]
    pub async fn load<'a, C: Clock>(
        tx: &Transaction<'a, C>,
        task_id: &TaskId,
    ) -> Result<Option<Self>, Error> {
        let task_info = match tx.task_info_for(task_id).await? {
            Some(task_info) => task_info,
            None => return Ok(None),
        };

        let stmt = tx
            .prepare_cached(
                "-- get_task_aggregation_counter()
SELECT
    COALESCE(SUM(success)::BIGINT, 0) AS success,
    COALESCE(SUM(duplicate_extension)::BIGINT, 0) as duplicate_extension,
    COALESCE(SUM(public_share_encode_failure)::BIGINT, 0) as public_share_encode_failure,
    COALESCE(SUM(batch_collected)::BIGINT, 0) AS batch_collected,
    COALESCE(SUM(report_replayed)::BIGINT, 0) AS report_replayed,
    COALESCE(SUM(report_dropped)::BIGINT, 0) AS report_dropped,
    COALESCE(SUM(hpke_unknown_config_id)::BIGINT, 0) AS hpke_unknown_config_id,
    COALESCE(SUM(hpke_decrypt_failure)::BIGINT, 0) AS hpke_decrypt_failure,
    COALESCE(SUM(vdaf_prep_error)::BIGINT, 0) AS vdaf_prep_error,
    COALESCE(SUM(task_not_started)::BIGINT, 0) AS task_not_started,
    COALESCE(SUM(task_expired)::BIGINT, 0) AS task_expired,
    COALESCE(SUM(invalid_message)::BIGINT, 0) AS invalid_message,
    COALESCE(SUM(report_too_early)::BIGINT, 0) AS report_too_early,
    COALESCE(SUM(helper_batch_collected)::BIGINT, 0) AS helper_batch_collected,
    COALESCE(SUM(helper_report_replayed)::BIGINT, 0) AS helper_report_replayed,
    COALESCE(SUM(helper_report_dropped)::BIGINT, 0) AS helper_report_dropped,
    COALESCE(SUM(helper_hpke_unknown_config_id)::BIGINT, 0) AS helper_hpke_unknown_config_id,
    COALESCE(SUM(helper_hpke_decrypt_failure)::BIGINT, 0) AS helper_hpke_decrypt_failure,
    COALESCE(SUM(helper_vdaf_prep_error)::BIGINT, 0) AS helper_vdaf_prep_error,
    COALESCE(SUM(helper_task_not_started)::BIGINT, 0) AS helper_task_not_started,
    COALESCE(SUM(helper_task_expired)::BIGINT, 0) AS helper_task_expired,
    COALESCE(SUM(helper_invalid_message)::BIGINT, 0) AS helper_invalid_message,
    COALESCE(SUM(helper_report_too_early)::BIGINT, 0) AS helper_report_too_early
FROM task_aggregation_counters
WHERE task_id = $1",
            )
            .await?;

        tx.query_opt(&stmt, &[/* task_id */ &task_info.pkey])
            .await?
            .map(|row| {
                Ok(Self::new_with_values(
                    row.get_bigint_and_convert("success")?,
                    row.get_bigint_and_convert("duplicate_extension")?,
                    row.get_bigint_and_convert("public_share_encode_failure")?,
                    row.get_bigint_and_convert("batch_collected")?,
                    row.get_bigint_and_convert("report_replayed")?,
                    row.get_bigint_and_convert("report_dropped")?,
                    row.get_bigint_and_convert("hpke_unknown_config_id")?,
                    row.get_bigint_and_convert("hpke_decrypt_failure")?,
                    row.get_bigint_and_convert("vdaf_prep_error")?,
                    row.get_bigint_and_convert("task_not_started")?,
                    row.get_bigint_and_convert("task_expired")?,
                    row.get_bigint_and_convert("invalid_message")?,
                    row.get_bigint_and_convert("report_too_early")?,
                    row.get_bigint_and_convert("helper_batch_collected")?,
                    row.get_bigint_and_convert("helper_report_replayed")?,
                    row.get_bigint_and_convert("helper_report_dropped")?,
                    row.get_bigint_and_convert("helper_hpke_unknown_config_id")?,
                    row.get_bigint_and_convert("helper_hpke_decrypt_failure")?,
                    row.get_bigint_and_convert("helper_vdaf_prep_error")?,
                    row.get_bigint_and_convert("helper_task_not_started")?,
                    row.get_bigint_and_convert("helper_task_expired")?,
                    row.get_bigint_and_convert("helper_invalid_message")?,
                    row.get_bigint_and_convert("helper_report_too_early")?,
                ))
            })
            .transpose()
    }

    /// Add the values in this counter to the counts persisted for the given [`TaskId`]. This is
    /// sharded, requiring an `ord` parameter to determine which shard to add to. `ord` should be
    /// randomly generated by the caller.
    #[tracing::instrument(skip(tx), err(level = Level::DEBUG))]
    pub async fn flush<'a, C: Clock>(
        self,
        task_id: &TaskId,
        tx: &Transaction<'a, C>,
        ord: u64,
    ) -> Result<(), Error> {
        let task_info = match tx.task_info_for(task_id).await? {
            Some(task_info) => task_info,
            None => return Err(Error::MutationTargetNotFound),
        };

        // Copy the inner counter values so we don't have to hold a sync Mutex across await points
        let inner = *self.inner.lock().unwrap();

        let stmt = tx
            .prepare_cached(
                "-- increment_task_aggregation_counter()
INSERT INTO task_aggregation_counters (task_id, ord, success, duplicate_extension,
public_share_encode_failure, batch_collected, report_replayed, report_dropped,
hpke_unknown_config_id, hpke_decrypt_failure, vdaf_prep_error, task_not_started, task_expired,
invalid_message, report_too_early, helper_batch_collected, helper_report_replayed,
helper_report_dropped, helper_hpke_unknown_config_id, helper_hpke_decrypt_failure,
helper_vdaf_prep_error, helper_task_not_started, helper_task_expired, helper_invalid_message,
helper_report_too_early)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
    $21, $22, $23, $24, $25)
ON CONFLICT (task_id, ord) DO UPDATE SET
    success = task_aggregation_counters.success + $3,
    duplicate_extension = task_aggregation_counters.duplicate_extension + $4,
    public_share_encode_failure = task_aggregation_counters.public_share_encode_failure + $5,
    batch_collected = task_aggregation_counters.batch_collected + $6,
    report_replayed = task_aggregation_counters.report_replayed + $7,
    report_dropped = task_aggregation_counters.report_dropped + $8,
    hpke_unknown_config_id = task_aggregation_counters.hpke_unknown_config_id + $9,
    hpke_decrypt_failure = task_aggregation_counters.hpke_decrypt_failure + $10,
    vdaf_prep_error = task_aggregation_counters.vdaf_prep_error + $11,
    task_not_started = task_aggregation_counters.task_not_started + $12,
    task_expired = task_aggregation_counters.task_expired + $13,
    invalid_message = task_aggregation_counters.invalid_message + $14,
    report_too_early = task_aggregation_counters.report_too_early + $15,
    helper_batch_collected = task_aggregation_counters.helper_batch_collected + $16,
    helper_report_replayed = task_aggregation_counters.helper_report_replayed + $17,
    helper_report_dropped = task_aggregation_counters.helper_report_dropped + $18,
    helper_hpke_unknown_config_id = task_aggregation_counters.helper_hpke_unknown_config_id + $19,
    helper_hpke_decrypt_failure = task_aggregation_counters.helper_hpke_decrypt_failure + $20,
    helper_vdaf_prep_error = task_aggregation_counters.helper_vdaf_prep_error + $21,
    helper_task_not_started = task_aggregation_counters.helper_task_not_started + $22,
    helper_task_expired = task_aggregation_counters.helper_task_expired + $23,
    helper_invalid_message = task_aggregation_counters.helper_invalid_message + $24,
    helper_report_too_early = task_aggregation_counters.helper_report_too_early + $25",
            )
            .await?;

        check_single_row_mutation(
            tx.execute(
                &stmt,
                &[
                    /* task_id */ &task_info.pkey,
                    /* ord */ &i64::try_from(ord)?,
                    /* success */ &i64::try_from(inner.success)?,
                    /* duplicate_extension */ &i64::try_from(inner.duplicate_extension)?,
                    /* public_share_encode_failure */
                    &i64::try_from(inner.public_share_encode_failure)?,
                    /* batch_collected */ &i64::try_from(inner.batch_collected)?,
                    /* report_replayed */ &i64::try_from(inner.report_replayed)?,
                    /* report_dropped */ &i64::try_from(inner.report_dropped)?,
                    /* hpke_unknown_config_id */
                    &i64::try_from(inner.hpke_unknown_config_id)?,
                    /* hpke_decrypt_failure */ &i64::try_from(inner.hpke_decrypt_failure)?,
                    /* vdaf_prep_error */ &i64::try_from(inner.vdaf_prep_error)?,
                    /* task_not_started */ &i64::try_from(inner.task_not_started)?,
                    /* task_expired */ &i64::try_from(inner.task_expired)?,
                    /* invalid_message */ &i64::try_from(inner.invalid_message)?,
                    /* report_too_early */ &i64::try_from(inner.report_too_early)?,
                    /* helper_batch_collected */
                    &i64::try_from(inner.helper_batch_collected)?,
                    /* helper_report_replayed */
                    &i64::try_from(inner.helper_report_replayed)?,
                    /* helper_report_dropped */
                    &i64::try_from(inner.helper_report_dropped)?,
                    /* helper_hpke_unknown_config_id */
                    &i64::try_from(inner.helper_hpke_unknown_config_id)?,
                    /* helper_hpke_decrypt_failure */
                    &i64::try_from(inner.helper_hpke_decrypt_failure)?,
                    /* helper_vdaf_prep_error */
                    &i64::try_from(inner.helper_vdaf_prep_error)?,
                    /* helper_task_not_started */
                    &i64::try_from(inner.helper_task_not_started)?,
                    /* helper_task_expired */ &i64::try_from(inner.helper_task_expired)?,
                    /* helper_invalid_message */
                    &i64::try_from(inner.helper_invalid_message)?,
                    /* helper_report_too_early */
                    &i64::try_from(inner.helper_report_too_early)?,
                ],
            )
            .await?,
        )
    }

    /// Returns true if and only if this task aggregation counter is "zero", i.e. it would not
    /// change the state of the written task aggregation counters.
    pub fn is_zero(&self) -> bool {
        self == &TaskAggregationCounter::default()
    }

    /// Increments the counter of successfully-aggregated reports.
    pub fn increment_success(&self) {
        self.inner.lock().unwrap().success += 1
    }

    /// Increments the appropriate counter based on the prepare failure.
    pub fn increment_with_report_error(&self, error: ReportError) {
        match error {
            ReportError::BatchCollected => self.inner.lock().unwrap().batch_collected += 1,
            ReportError::ReportReplayed => self.inner.lock().unwrap().report_replayed += 1,
            ReportError::ReportDropped => self.inner.lock().unwrap().report_dropped += 1,
            ReportError::HpkeUnknownConfigId => {
                self.inner.lock().unwrap().hpke_unknown_config_id += 1
            }
            ReportError::HpkeDecryptError => self.inner.lock().unwrap().hpke_decrypt_failure += 1,
            ReportError::VdafPrepError => self.inner.lock().unwrap().vdaf_prep_error += 1,
            ReportError::TaskNotStarted => self.inner.lock().unwrap().task_not_started += 1,
            ReportError::TaskExpired => self.inner.lock().unwrap().task_expired += 1,
            ReportError::InvalidMessage => self.inner.lock().unwrap().invalid_message += 1,
            ReportError::ReportTooEarly => self.inner.lock().unwrap().report_too_early += 1,
            _ => tracing::debug!(?error, "unexpected prepare error"),
        }
    }

    /// Increments the appropriate counter based on the helper prepare failure.
    pub fn increment_with_helper_report_error(&self, helper_error: ReportError) {
        match helper_error {
            ReportError::BatchCollected => self.inner.lock().unwrap().helper_batch_collected += 1,
            ReportError::ReportReplayed => self.inner.lock().unwrap().helper_report_replayed += 1,
            ReportError::ReportDropped => self.inner.lock().unwrap().helper_report_dropped += 1,
            ReportError::HpkeUnknownConfigId => {
                self.inner.lock().unwrap().helper_hpke_unknown_config_id += 1
            }
            ReportError::HpkeDecryptError => {
                self.inner.lock().unwrap().helper_hpke_decrypt_failure += 1
            }
            ReportError::VdafPrepError => self.inner.lock().unwrap().helper_vdaf_prep_error += 1,
            ReportError::TaskNotStarted => self.inner.lock().unwrap().helper_task_not_started += 1,
            ReportError::TaskExpired => self.inner.lock().unwrap().helper_task_expired += 1,
            ReportError::InvalidMessage => self.inner.lock().unwrap().helper_invalid_message += 1,
            ReportError::ReportTooEarly => self.inner.lock().unwrap().helper_report_too_early += 1,
            _ => tracing::debug!(?helper_error, "unexpected prepare error from helper"),
        }
    }
}
