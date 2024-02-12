use crate::aggregator::{query_type::UploadableQueryType, Error};
use async_trait::async_trait;
use futures::future::join_all;
use janus_aggregator_core::datastore::{
    self,
    models::{LeaderStoredReport, TaskUploadIncrementor},
    Datastore, Transaction,
};
use janus_core::{time::Clock, Runtime};
use janus_messages::TaskId;
use prio::vdaf;
use rand::{thread_rng, Rng};
use std::{fmt::Debug, marker::PhantomData, mem::replace, sync::Arc, time::Duration};
use tokio::{
    select,
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};
use tracing::debug;

use super::error::ReportRejection;

type ReportResult<C> = Result<Box<dyn ReportWriter<C>>, ReportRejection>;

type ResultSender = oneshot::Sender<Result<(), Arc<Error>>>;

type ReportWriteBatcherSender<C> = mpsc::Sender<(ReportResult<C>, Option<ResultSender>)>;
type ReportWriteBatcherReceiver<C> = mpsc::Receiver<(ReportResult<C>, Option<ResultSender>)>;

pub struct ReportWriteBatcher<C> {
    report_tx: ReportWriteBatcherSender<C>,
}

impl<C: Clock> ReportWriteBatcher<C> {
    pub fn new<R: Runtime + Send + Sync + 'static>(
        ds: Arc<Datastore<C>>,
        runtime: R,
        enable_task_counters: bool,
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
                enable_task_counters,
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
        enable_task_counters: bool,
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
                    Self::write_batch(
                        ds,
                        enable_task_counters,
                        counter_shard_count,
                        report_results,
                    )
                    .await;
                });
            }
        }
    }

    #[tracing::instrument(skip_all)]
    async fn write_batch(
        ds: Arc<Datastore<C>>,
        enable_task_counters: bool,
        counter_shard_count: u64,
        mut report_results: Vec<(ReportResult<C>, Option<ResultSender>)>,
    ) {
        let ord = thread_rng().gen_range(0..counter_shard_count);

        // Sort by task ID to prevent deadlocks with concurrently running transactions. Since we are
        // using the same ord for all statements, we do not need to sort by ord.
        report_results.sort_unstable_by_key(|writer| match &writer.0 {
            Ok(report_writer) => *report_writer.task_id(),
            Err(rejection) => *rejection.task_id(),
        });

        // Run all report writes concurrently.
        let (report_results, result_senders): (Vec<ReportResult<C>>, Vec<Option<ResultSender>>) =
            report_results.into_iter().unzip();
        let report_results = Arc::new(report_results);
        let results = ds
            .run_tx("upload", |tx| {
                let report_results = Arc::clone(&report_results);
                Box::pin(async move {
                    Ok(
                        join_all(report_results.iter().map(|report_result| async move {
                            match report_result {
                                Ok(report_writer) => {
                                    report_writer
                                        .write_report(tx, enable_task_counters, ord)
                                        .await
                                }
                                Err(rejection) => {
                                    if enable_task_counters {
                                        tx.increment_task_upload_counter(
                                            rejection.task_id(),
                                            ord,
                                            &rejection.reason().into(),
                                        )
                                        .await?;
                                    }
                                    Ok(())
                                }
                            }
                        }))
                        .await,
                    )
                })
            })
            .await;

        match results {
            Ok(results) => {
                // Individual, per-request results.
                assert_eq!(result_senders.len(), results.len()); // sanity check: should be guaranteed.
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
    fn task_id(&self) -> &TaskId;
    async fn write_report(
        &self,
        tx: &Transaction<C>,
        enable_task_counters: bool,
        ord: u64,
    ) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct WritableReport<const SEED_SIZE: usize, Q, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
    A::InputShare: PartialEq + Send + Sync,
    A::PublicShare: PartialEq + Send + Sync,
    A::AggregationParam: Send + Sync,
    A::AggregateShare: Send + Sync,
    Q: UploadableQueryType,
{
    vdaf: Arc<A>,
    report: LeaderStoredReport<SEED_SIZE, A>,
    _phantom_q: PhantomData<Q>,
}

impl<const SEED_SIZE: usize, Q, A> WritableReport<SEED_SIZE, Q, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
    A::InputShare: PartialEq + Send + Sync,
    A::PublicShare: PartialEq + Send + Sync,
    A::AggregationParam: Send + Sync,
    A::AggregateShare: Send + Sync,
    Q: UploadableQueryType,
{
    pub fn new(vdaf: Arc<A>, report: LeaderStoredReport<SEED_SIZE, A>) -> Self {
        Self {
            vdaf,
            report,
            _phantom_q: PhantomData::<Q>,
        }
    }
}

#[async_trait]
impl<const SEED_SIZE: usize, C, Q, A> ReportWriter<C> for WritableReport<SEED_SIZE, Q, A>
where
    A: vdaf::Aggregator<SEED_SIZE, 16> + Send + Sync + 'static,
    A::InputShare: PartialEq + Send + Sync,
    A::PublicShare: PartialEq + Send + Sync,
    A::AggregationParam: Send + Sync,
    A::AggregateShare: Send + Sync,
    C: Clock,
    Q: UploadableQueryType,
{
    fn task_id(&self) -> &TaskId {
        self.report.task_id()
    }

    async fn write_report(
        &self,
        tx: &Transaction<C>,
        enable_task_counters: bool,
        ord: u64,
    ) -> Result<(), Error> {
        // Some validation requires we query the database. Thus it's still possible to reject a
        // report at this stage.
        match Q::validate_uploaded_report(tx, self.vdaf.as_ref(), &self.report).await {
            Ok(_) => {
                let result = tx
                    .put_client_report::<SEED_SIZE, A>(&self.vdaf, &self.report)
                    .await;
                match result {
                    Ok(_) => {
                        if enable_task_counters {
                            tx.increment_task_upload_counter(
                                self.report.task_id(),
                                ord,
                                &TaskUploadIncrementor::ReportSuccess,
                            )
                            .await?;
                        }
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
                    if enable_task_counters {
                        tx.increment_task_upload_counter(
                            rejection.task_id(),
                            ord,
                            &rejection.reason().into(),
                        )
                        .await?;
                    }
                }
                Err(error)
            }
        }
    }
}
