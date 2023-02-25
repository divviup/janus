use super::{query_type::UploadableQueryType, Error};
use crate::datastore::{self, models::LeaderStoredReport, Datastore, Transaction};
use async_trait::async_trait;
use futures::future::join_all;
use janus_core::time::Clock;
use prio::vdaf;
use std::{fmt::Debug, marker::PhantomData, mem::replace, sync::Arc, time::Duration};
use tokio::{
    select,
    sync::{mpsc, oneshot},
    time::{sleep_until, Instant},
};

type ReportWriteBatcherSender<C> = mpsc::Sender<(
    Box<dyn ReportWriter<C>>,
    oneshot::Sender<Result<(), Arc<Error>>>,
)>;
type ReportWriteBatcherReceiver<C> = mpsc::Receiver<(
    Box<dyn ReportWriter<C>>,
    oneshot::Sender<Result<(), Arc<Error>>>,
)>;

pub struct ReportWriteBatcher<C: Clock> {
    report_tx: ReportWriteBatcherSender<C>,
}

impl<C: Clock> ReportWriteBatcher<C> {
    pub fn new(
        ds: Arc<Datastore<C>>,
        max_batch_size: usize,
        max_batch_write_delay: Duration,
    ) -> Self {
        let (report_tx, report_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            Self::run_upload_batcher(ds, report_rx, max_batch_size, max_batch_write_delay).await
        });

        Self { report_tx }
    }

    pub async fn write_report<R: ReportWriter<C> + 'static>(
        &self,
        report: R,
    ) -> Result<(), Arc<Error>> {
        // Send report to be written.
        // Unwrap safety: report_rx is not dropped until ReportWriteBatcher is dropped.
        let (rslt_tx, rslt_rx) = oneshot::channel();
        self.report_tx
            .send((Box::new(report), rslt_tx))
            .await
            .unwrap();

        // Await the result of writing the report.
        // Unwrap safety: rslt_tx is always sent on before being dropped, and is never closed.
        rslt_rx.await.unwrap()
    }

    async fn run_upload_batcher(
        ds: Arc<Datastore<C>>,
        mut report_rx: ReportWriteBatcherReceiver<C>,
        max_batch_size: usize,
        max_batch_write_delay: Duration,
    ) {
        let mut is_done = false;
        let mut batch_expiry = Instant::now();
        let mut report_writers = Vec::with_capacity(max_batch_size);
        let mut result_txs = Vec::with_capacity(max_batch_size);
        while !is_done {
            // Wait for an event of interest.
            let write_batch = select! {
                // Wait until we receive a report to be written (or the channel is closed due to the
                // ReportWriteBatcher being dropped)...
                item = report_rx.recv() => {
                    match item {
                        // We got an item. Add it to the current batch of reports to be written.
                        Some((report_writer, rslt_tx)) => {
                            if report_writers.is_empty() {
                                batch_expiry = Instant::now() + max_batch_write_delay;
                            }
                            report_writers.push(report_writer);
                            result_txs.push(rslt_tx);
                            report_writers.len() >= max_batch_size
                        }

                        // The channel is closed. Note this, and write any final reports that may be
                        // batched before shutting down.
                        None => {
                            is_done = true;
                            !report_writers.is_empty()
                        },
                    }
                },

                // ... or the current batch times out.
                _ = sleep_until(batch_expiry), if !report_writers.is_empty() => true,
            };

            // If the event made us want to write the current batch to storage, do so.
            if write_batch {
                let ds = Arc::clone(&ds);
                let result_writers =
                    replace(&mut report_writers, Vec::with_capacity(max_batch_size));
                let result_txs = replace(&mut result_txs, Vec::with_capacity(max_batch_size));
                tokio::spawn(async move {
                    Self::write_batch(ds, result_writers, result_txs).await;
                });
            }
        }
    }

    async fn write_batch(
        ds: Arc<Datastore<C>>,
        report_writers: Vec<Box<dyn ReportWriter<C>>>,
        result_txs: Vec<oneshot::Sender<Result<(), Arc<Error>>>>,
    ) {
        // Check preconditions.
        assert_eq!(report_writers.len(), result_txs.len());

        // Run all report writes concurrently.
        let report_writers = Arc::new(report_writers);
        let rslts = ds
            .run_tx_with_name("upload", |tx| {
                let report_writers = Arc::clone(&report_writers);
                Box::pin(async move {
                    Ok(join_all(report_writers.iter().map(|rw| rw.write_report(tx))).await)
                })
            })
            .await;

        match rslts {
            Ok(rslts) => {
                // Individual, per-request results.
                assert_eq!(result_txs.len(), rslts.len()); // sanity check: should be guaranteed.
                for (rslt_tx, rslt) in result_txs.into_iter().zip(rslts.into_iter()) {
                    let _ = rslt_tx.send(rslt.map_err(|err| Arc::new(Error::from(err))));
                }
            }
            Err(err) => {
                // Total-transaction failures are given to all waiting report uploaders.
                let err = Arc::new(Error::from(err));
                for rslt_tx in result_txs.into_iter() {
                    let _ = rslt_tx.send(Err(Arc::clone(&err)));
                }
            }
        };
    }
}

#[async_trait]
pub trait ReportWriter<C: Clock>: Debug + Send + Sync {
    async fn write_report(&self, tx: &Transaction<C>) -> Result<(), datastore::Error>;
}

#[derive(Debug)]
pub struct WritableReport<const L: usize, Q, A>
where
    A: vdaf::Aggregator<L> + Send + Sync + 'static,
    A::InputShare: PartialEq + Send + Sync,
    A::PublicShare: PartialEq + Send + Sync,
    A::AggregationParam: Send + Sync,
    A::AggregateShare: Send + Sync,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    Q: UploadableQueryType,
{
    vdaf: Arc<A>,
    report: LeaderStoredReport<L, A>,
    _phantom_q: PhantomData<Q>,
}

impl<const L: usize, Q, A> WritableReport<L, Q, A>
where
    A: vdaf::Aggregator<L> + Send + Sync + 'static,
    A::InputShare: PartialEq + Send + Sync,
    A::PublicShare: PartialEq + Send + Sync,
    A::AggregationParam: Send + Sync,
    A::AggregateShare: Send + Sync,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    Q: UploadableQueryType,
{
    pub fn new(vdaf: Arc<A>, report: LeaderStoredReport<L, A>) -> Self {
        Self {
            vdaf,
            report,
            _phantom_q: PhantomData::<Q>,
        }
    }
}

#[async_trait]
impl<const L: usize, C, Q, A> ReportWriter<C> for WritableReport<L, Q, A>
where
    A: vdaf::Aggregator<L> + Send + Sync + 'static,
    A::InputShare: PartialEq + Send + Sync,
    A::PublicShare: PartialEq + Send + Sync,
    A::AggregationParam: Send + Sync,
    A::AggregateShare: Send + Sync,
    for<'a> <A::AggregateShare as TryFrom<&'a [u8]>>::Error: Debug,
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    C: Clock,
    Q: UploadableQueryType,
{
    async fn write_report(&self, tx: &Transaction<C>) -> Result<(), datastore::Error> {
        Q::validate_uploaded_report(tx, &self.report).await?;

        // Store the report.
        match tx.put_client_report::<L, A>(&self.vdaf, &self.report).await {
            Ok(()) => Ok(()),

            // Reject reports whose report IDs have been seen before.
            // https://datatracker.ietf.org/doc/html/draft-ietf-ppm-dap-03#section-4.3.2-16
            Err(datastore::Error::MutationTargetAlreadyExists) => Err(datastore::Error::User(
                Error::ReportRejected(
                    *self.report.task_id(),
                    *self.report.metadata().id(),
                    *self.report.metadata().time(),
                )
                .into(),
            )),

            err => err,
        }
    }
}
