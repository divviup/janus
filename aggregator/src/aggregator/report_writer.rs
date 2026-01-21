use crate::aggregator::{
    Error,
    batch_mode::UploadableBatchMode,
    error::{ReportRejection, ReportRejectionReason},
};
use async_trait::async_trait;
use futures::future::{join_all, try_join_all};
use janus_aggregator_core::{
    AsyncAggregator,
    datastore::{
        self, Datastore, Transaction, models::LeaderStoredReport, task_counters::TaskUploadCounter,
    },
};
use janus_core::{Runtime, time::Clock};
use janus_messages::TaskId;
use rand::{Rng, rng};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    marker::PhantomData,
    mem::{replace, take},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{
    select,
    sync::{mpsc, oneshot},
    time::{Instant, sleep_until},
};
use tracing::{debug, error};

type ReportResult<C> = Result<Box<dyn ReportWriter<C>>, ReportRejection>;

type ResultSender = oneshot::Sender<Result<(), Arc<Error>>>;

type ReportWriteBatcherSender<C> = mpsc::Sender<(ReportResult<C>, Option<ResultSender>)>;
type ReportWriteBatcherReceiver<C> = mpsc::Receiver<(ReportResult<C>, Option<ResultSender>)>;

#[derive(Debug)]
pub struct ReportWriteBatcher<C> {
    report_tx: ReportWriteBatcherSender<C>,
}

impl<C: Clock> ReportWriteBatcher<C> {
    pub fn new<R: Runtime + Send + Sync + 'static>(
        ds: Arc<Datastore<C>>,
        runtime: R,
        counter_shard_count: u64,
        max_batch_size: usize,
        max_batch_write_delay: Duration,
    ) -> Self {
        let (report_tx, report_rx) = mpsc::channel(1);

        let runtime = Arc::new(runtime);
        let runtime_clone = Arc::clone(&runtime);
        runtime.spawn(async move {
            Self::run_upload_batcher(
                ds,
                runtime_clone,
                report_rx,
                counter_shard_count,
                max_batch_size,
                max_batch_write_delay,
            )
            .await
        });

        Self { report_tx }
    }

    /// Save a report rejection to the database.
    ///
    /// This function does not wait for the result of the batch write, because we do not want
    /// clients to retry bad reports, even due to server error.
    pub async fn write_rejection(&self, report_rejection: ReportRejection) {
        // Unwrap safety: report_rx is not dropped until ReportWriteBatcher is dropped.
        self.report_tx
            .send((Err(report_rejection), None))
            .await
            .unwrap();
    }

    /// Save a report to the database.
    ///
    /// This function waits for and returns the result of the batch write.
    pub async fn write_report(
        &self,
        report_writer: Box<dyn ReportWriter<C>>,
    ) -> Result<(), Arc<Error>> {
        // Send report to be written.
        // Unwrap safety: report_rx is not dropped until ReportWriteBatcher is dropped.
        let (result_tx, result_rx) = oneshot::channel();
        self.report_tx
            .send((Ok(report_writer), Some(result_tx)))
            .await
            .unwrap();

        // Await the result of writing the report.
        // Unwrap safety: rslt_tx is always sent on before being dropped, and is never closed.
        result_rx.await.unwrap()
    }

    #[tracing::instrument(
        name = "ReportWriteBatcher::run_upload_batcher",
        skip(ds, runtime, report_rx)
    )]
    async fn run_upload_batcher<R: Runtime + Send + Sync>(
        ds: Arc<Datastore<C>>,
        runtime: Arc<R>,
        mut report_rx: ReportWriteBatcherReceiver<C>,
        counter_shard_count: u64,
        max_batch_size: usize,
        max_batch_write_delay: Duration,
    ) {
        let mut is_done = false;
        let mut batch_expiry = Instant::now();
        let mut report_results = Vec::with_capacity(max_batch_size);
        while !is_done {
            // Wait for an event of interest.
            let write_batch = select! {
                // Wait until we receive a report to be written, or the channel is closed due to the
                // ReportWriteBatcher being dropped...
                item = report_rx.recv() => {
                    match item {
                        // We got an item. Add it to the current batch of reports to be written.
                        Some(report) => {
                            if report_results.is_empty() {
                                batch_expiry = Instant::now() + max_batch_write_delay;
                            }
                            report_results.push(report);
                            report_results.len() >= max_batch_size
                        }

                        // The channel is closed. Note this, and write any final reports that may be
                        // batched before shutting down.
                        None => {
                            is_done = true;
                            !report_results.is_empty()
                        },
                    }
                },

                // ... or the current batch, if there is one, times out.
                _ = sleep_until(batch_expiry), if !report_results.is_empty() => true,
            };

            // If the event made us want to write the current batch to storage, do so.
            if write_batch {
                let ds = Arc::clone(&ds);
                let report_results =
                    replace(&mut report_results, Vec::with_capacity(max_batch_size));
                runtime.spawn(async move {
                    Self::write_batch(ds, counter_shard_count, report_results).await;
                });
            }
        }
    }

    #[tracing::instrument(name = "ReportWriteBatcher::write_batch", skip_all)]
    async fn write_batch(
        ds: Arc<Datastore<C>>,
        counter_shard_count: u64,
        report_results: Vec<(ReportResult<C>, Option<ResultSender>)>,
    ) {
        // Run all report writes concurrently.
        let (report_results, result_senders): (Vec<ReportResult<C>>, Vec<Option<ResultSender>>) =
            report_results.into_iter().unzip();
        let report_results = Arc::new(report_results);
        let results = ds
            .run_tx("upload", |tx| {
                let report_results = Arc::clone(&report_results);
                Box::pin(async move {
                    let task_upload_counters = TaskUploadCounters::default();
                    let results = join_all(report_results.iter().map(|report_result| {
                        let task_upload_counters = task_upload_counters.clone();
                        async move {
                            match report_result {
                                Ok(report_writer) => {
                                    report_writer.write_report(tx, &task_upload_counters).await
                                }
                                Err(rejection) => {
                                    task_upload_counters.increment_report_rejection(rejection);
                                    Ok(())
                                }
                            }
                        }
                    }))
                    .await;
                    Ok((results, task_upload_counters))
                })
            })
            .await;

        match results {
            Ok((results, task_upload_counters)) => {
                // Write the task upload counters in a separate transaction from uploads. This is
                // to prevent seralization conflicts causing excess repeated work when INSERTing.
                //
                // We're fine with this being non-transactional with the actual report uploads.
                // If the process dies before being able to write counters, it's not a big deal.
                let _ = ds
                    .run_tx("update_task_upload_counters", |tx| {
                        let task_upload_counters = task_upload_counters.clone();
                        Box::pin(async move {
                            task_upload_counters.write(counter_shard_count, tx).await
                        })
                    })
                    .await
                    .map_err(|err| error!(?err, "Failed to write upload metrics"));

                // Individual, per-request results.
                //
                // sanity check: should be guaranteed.
                assert_eq!(result_senders.len(), results.len());
                for (result_tx, result) in result_senders.into_iter().zip(results.into_iter()) {
                    if let Some(result_tx) = result_tx {
                        if result_tx.send(result.map_err(Arc::new)).is_err() {
                            debug!(
                                "ReportWriter couldn't send result to requester (request cancelled?)"
                            );
                        }
                    }
                }
            }
            Err(err) => {
                // Total-transaction failures are given to all waiting report uploaders.
                let err = Arc::new(Error::from(err));
                result_senders.into_iter().flatten().for_each(|result_tx| {
                    if result_tx.send(Err(Arc::clone(&err))).is_err() {
                        debug!(
                            "ReportWriter couldn't send result to requester (request cancelled?)"
                        );
                    };
                })
            }
        };
    }
}

#[async_trait]
pub trait ReportWriter<C: Clock>: Debug + Send + Sync {
    async fn write_report(
        &self,
        tx: &Transaction<C>,
        task_upload_counters: &TaskUploadCounters,
    ) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct WritableReport<const SEED_SIZE: usize, B, A>
where
    A: AsyncAggregator<SEED_SIZE>,
    B: UploadableBatchMode,
{
    vdaf: Arc<A>,
    report: LeaderStoredReport<SEED_SIZE, A>,
    _phantom_q: PhantomData<B>,
}

impl<const SEED_SIZE: usize, B, A> WritableReport<SEED_SIZE, B, A>
where
    A: AsyncAggregator<SEED_SIZE>,
    B: UploadableBatchMode,
{
    pub fn new(vdaf: Arc<A>, report: LeaderStoredReport<SEED_SIZE, A>) -> Self {
        Self {
            vdaf,
            report,
            _phantom_q: PhantomData::<B>,
        }
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, C, B, A> ReportWriter<C> for WritableReport<SEED_SIZE, B, A>
where
    A: AsyncAggregator<SEED_SIZE>,
    C: Clock,
    B: UploadableBatchMode,
{
    async fn write_report(
        &self,
        tx: &Transaction<C>,
        task_upload_counter: &TaskUploadCounters,
    ) -> Result<(), Error> {
        // Some validation requires we query the database. Thus it's still possible to reject a
        // report at this stage.
        match B::validate_uploaded_report(tx, self.vdaf.as_ref(), &self.report).await {
            Ok(_) => {
                let result = tx.put_client_report::<SEED_SIZE, A>(&self.report).await;
                match result {
                    Ok(_) => {
                        task_upload_counter.increment_report_success(self.report.task_id());
                        Ok(())
                    }
                    // Assume this was a duplicate report, return OK but don't increment the counter
                    // so we avoid double counting successful reports.
                    Err(datastore::Error::MutationTargetAlreadyExists) => Ok(()),
                    Err(error) => Err(error.into()),
                }
            }
            Err(error) => {
                if let Error::ReportRejected(rejection) = error {
                    task_upload_counter.increment_report_rejection(&rejection);
                }
                Err(error)
            }
        }
    }
}

/// A collection of [`TaskUploadCounter`]s, grouped by [`TaskId`]. It can be cloned to share it
/// across futures.
#[derive(Debug, Default, Clone)]
pub struct TaskUploadCounters(Arc<StdMutex<BTreeMap<TaskId, TaskUploadCounter>>>);

impl TaskUploadCounters {
    pub fn increment_report_success(&self, task_id: &TaskId) {
        // Unwrap safety: panic on mutex poisoning.
        self.0
            .lock()
            .unwrap()
            .entry(*task_id)
            .or_default()
            .increment_report_success();
    }

    pub fn increment_report_rejection(&self, report_rejection: &ReportRejection) {
        // Unwrap safety: panic on mutex poisoning.
        let mut map = self.0.lock().unwrap();
        let entry = map.entry(*report_rejection.task_id()).or_default();

        match report_rejection.reason() {
            ReportRejectionReason::IntervalCollected => entry.increment_interval_collected(),
            ReportRejectionReason::DecryptFailure => entry.increment_report_decrypt_failure(),
            ReportRejectionReason::DecodeFailure => entry.increment_report_decode_failure(),
            ReportRejectionReason::TaskEnded => entry.increment_task_ended(),
            ReportRejectionReason::Expired => entry.increment_report_expired(),
            ReportRejectionReason::TooEarly => entry.increment_report_too_early(),
            ReportRejectionReason::OutdatedHpkeConfig(_) => entry.increment_report_outdated_key(),
            ReportRejectionReason::TaskNotStarted => entry.increment_task_not_started(),
            ReportRejectionReason::DuplicateExtension => entry.increment_duplicate_extension(),
        }
    }

    /// Flushes the stored [`TaskUploadCounter`]s to the database. The stored counters are cleared.
    async fn write<C: Clock>(
        &self,
        counter_shard_count: u64,
        tx: &Transaction<'_, C>,
    ) -> Result<(), datastore::Error> {
        let ord = rng().random_range(0..counter_shard_count);
        let map = {
            // Unwrap safety: panic on mutex poisoning.
            let mut lock = self.0.lock().unwrap();
            take(&mut *lock)
        };

        // The order of elements returned by a BTreeMap iterator are sorted. This allows us to
        // discourage database deadlocks when multiple tasks are being incremented in the same
        // transaction. This doesn't fully prevent deadlocks since we execute the statements
        // concurrently--it's not guaranteed that order is preserved when the futures are being
        // advanced.
        try_join_all(
            map.into_iter()
                .map(|(task_id, counter)| async move { counter.flush(&task_id, tx, ord).await }),
        )
        .await?;
        Ok(())
    }
}
