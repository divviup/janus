use anyhow::Result;
use futures::future::try_join_all;
use itertools::Itertools;
use janus::message::{Nonce, Time};
use janus::time::{Clock, RealClock};
use janus_server::binary_utils::{janus_main, BinaryOptions, CommonBinaryOptions};
use janus_server::config::AggregationJobCreatorConfig;
use janus_server::datastore::models::{
    AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
};
use janus_server::datastore::{self, Datastore};
use janus_server::job_creator::PerTaskJobCreator;
use janus_server::message::AggregationJobId;
use janus_server::task::{Task, VdafInstance};
use prio::codec::Encode;
use prio::vdaf;
use prio::vdaf::prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum};
use std::sync::Arc;
use structopt::StructOpt;
use tracing::{debug, error};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "janus-aggregation-job-creator",
    about = "Janus aggregation job creator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    #[structopt(flatten)]
    common: CommonBinaryOptions,
}

impl BinaryOptions for Options {
    fn common_options(&self) -> &CommonBinaryOptions {
        &self.common
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    janus_main::<Options, _, _, _, _>(
        RealClock::default(),
        |clock, config: AggregationJobCreatorConfig, datastore| async move {
            // Start creating aggregation jobs.
            Arc::new(PerTaskJobCreator::new(
                Arc::new(datastore),
                clock,
                config.job_creator_config,
                move |clock, datastore, task| async move {
                    AggregationJobCreator {
                        datastore,
                        clock,
                        min_aggregation_job_size: config.min_aggregation_job_size,
                        max_aggregation_job_size: config.max_aggregation_job_size,
                    }
                    .create_aggregation_jobs_for_task(&task)
                    .await
                },
            ))
            .run()
            .await;

            Ok(())
        },
    )
    .await
}

struct AggregationJobCreator<C: Clock> {
    // Dependencies.
    datastore: Arc<Datastore<C>>,
    clock: C,

    // Configuration values.
    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch unit only; historical batch units will create aggregation jobs of any size,
    /// on the theory that almost all reports will have be received for these batch units already.
    min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    max_aggregation_job_size: usize,
}

impl<C: Clock> AggregationJobCreator<C> {
    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task(&self, task: &Task) -> anyhow::Result<()> {
        match task.vdaf {
            VdafInstance::Prio3Aes128Count => {
                self.create_aggregation_jobs_for_task_no_param::<Prio3Aes128Count>(task)
                    .await
            }

            VdafInstance::Prio3Aes128Sum { .. } => {
                self.create_aggregation_jobs_for_task_no_param::<Prio3Aes128Sum>(task)
                    .await
            }

            VdafInstance::Prio3Aes128Histogram { .. } => {
                self.create_aggregation_jobs_for_task_no_param::<Prio3Aes128Histogram>(task)
                    .await
            }

            _ => {
                error!(vdaf = ?task.vdaf, "VDAF is not yet supported");
                panic!("VDAF {:?} is not yet supported", task.vdaf);
            }
        }
    }

    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task_no_param<A: vdaf::Aggregator<AggregationParam = ()>>(
        &self,
        task: &Task,
    ) -> anyhow::Result<()>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareStep: Send + Sync + Encode,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
    {
        let task_id = task.id;
        let min_batch_duration = task.min_batch_duration;
        let current_batch_unit_start = self
            .clock
            .now()
            .to_batch_unit_interval_start(min_batch_duration)?;

        let min_aggregation_job_size = self.min_aggregation_job_size;
        let max_aggregation_job_size = self.max_aggregation_job_size;

        Ok(self
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    // Find some unaggregated client reports, and group them by their batch unit.
                    let nonces_by_batch_unit = tx
                        .get_unaggregated_client_report_nonces_for_task(task_id)
                        .await?
                        .into_iter()
                        .map(|nonce| {
                            nonce
                                .time()
                                .to_batch_unit_interval_start(min_batch_duration)
                                .map(|s| (s, nonce))
                                .map_err(datastore::Error::from)
                        })
                        .collect::<Result<Vec<(Time, Nonce)>, _>>()?
                        .into_iter()
                        .into_group_map();

                    // Generate aggregation jobs & report aggregations based on the reports we read.
                    let mut agg_jobs = Vec::new();
                    let mut report_aggs = Vec::new();
                    for (batch_unit_start, nonces) in nonces_by_batch_unit {
                        for agg_job_nonces in nonces.chunks(max_aggregation_job_size) {
                            if batch_unit_start >= current_batch_unit_start
                                && agg_job_nonces.len() < min_aggregation_job_size
                            {
                                continue;
                            }

                            let aggregation_job_id = AggregationJobId::random();
                            debug!(
                                ?task_id,
                                ?aggregation_job_id,
                                report_count = agg_job_nonces.len(),
                                "Creating aggregation job"
                            );
                            agg_jobs.push(AggregationJob::<A> {
                                aggregation_job_id,
                                task_id,
                                aggregation_param: (),
                                state: AggregationJobState::InProgress,
                            });

                            for (ord, nonce) in agg_job_nonces.iter().enumerate() {
                                report_aggs.push(ReportAggregation::<A> {
                                    aggregation_job_id,
                                    task_id,
                                    nonce: *nonce,
                                    ord: i64::try_from(ord)?,
                                    state: ReportAggregationState::Start,
                                });
                            }
                        }
                    }

                    // Write the aggregation jobs & report aggregations we created.
                    try_join_all(
                        agg_jobs
                            .iter()
                            .map(|agg_job| tx.put_aggregation_job(agg_job)),
                    )
                    .await?;
                    try_join_all(
                        report_aggs
                            .iter()
                            .map(|report_agg| tx.put_report_aggregation(report_agg)),
                    )
                    .await?;

                    Ok(())
                })
            })
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::AggregationJobCreator;
    use futures::{future::try_join_all, TryFutureExt};
    use janus::{
        message::{Nonce, Report, Role, TaskId, Time},
        time::Clock,
    };
    use janus_server::{
        datastore::{Crypter, Datastore, Transaction},
        message::{test_util::new_dummy_report, AggregationJobId},
        task::{test_util::new_dummy_task, VdafInstance},
    };
    use janus_test_util::MockClock;
    use prio::vdaf::{prio3::Prio3Aes128Count, Vdaf as _};
    use std::{
        collections::{HashMap, HashSet},
        iter,
        sync::Arc,
    };

    janus_test_util::define_ephemeral_datastore!();

    #[tokio::test]
    async fn create_aggregation_jobs_for_task() {
        // Setup.
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        const MIN_AGGREGATION_JOB_SIZE: usize = 50;
        const MAX_AGGREGATION_JOB_SIZE: usize = 60;

        // Sanity check the constant values provided.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(1 < MIN_AGGREGATION_JOB_SIZE); // we can subtract 1 safely
            assert!(MIN_AGGREGATION_JOB_SIZE < MAX_AGGREGATION_JOB_SIZE);
            assert!(MAX_AGGREGATION_JOB_SIZE < usize::MAX); // we can add 1 safely
        }

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
        let current_batch_unit = clock
            .now()
            .to_batch_unit_interval_start(task.min_batch_duration)
            .unwrap();

        // In the current batch unit, create MIN_AGGREGATION_JOB_SIZE reports. We expect an
        // aggregation job to be created containing these reports.
        let report_time = clock.now();
        let cur_batch_unit_reports: Vec<Report> =
            iter::repeat_with(|| new_dummy_report(task_id, report_time))
                .take(MIN_AGGREGATION_JOB_SIZE)
                .collect();

        // In a previous "small" batch unit, create fewer than MIN_AGGREGATION_JOB_SIZE reports.
        // Since the minimum aggregation job size applies only to the current batch window, we
        // expect an aggregation job to be created for these reports.
        let report_time = report_time.sub(task.min_batch_duration).unwrap();
        let small_batch_unit_reports: Vec<Report> =
            iter::repeat_with(|| new_dummy_report(task_id, report_time))
                .take(MIN_AGGREGATION_JOB_SIZE - 1)
                .collect();

        // In a (separate) previous "big" batch unit, create more than MAX_AGGREGATION_JOB_SIZE
        // reports. We expect these reports will be split into more than one aggregation job.
        let report_time = report_time.sub(task.min_batch_duration).unwrap();
        let big_batch_unit_reports: Vec<Report> =
            iter::repeat_with(|| new_dummy_report(task_id, report_time))
                .take(MAX_AGGREGATION_JOB_SIZE + 1)
                .collect();

        let all_nonces: HashSet<Nonce> = cur_batch_unit_reports
            .iter()
            .chain(&small_batch_unit_reports)
            .chain(&big_batch_unit_reports)
            .map(|report| report.nonce())
            .collect();

        ds.run_tx(|tx| {
            let task = task.clone();
            let (cur_batch_unit_reports, small_batch_unit_reports, big_batch_unit_reports) = (
                cur_batch_unit_reports.clone(),
                small_batch_unit_reports.clone(),
                big_batch_unit_reports.clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                for report in cur_batch_unit_reports
                    .iter()
                    .chain(&small_batch_unit_reports)
                    .chain(&big_batch_unit_reports)
                {
                    tx.put_client_report(report).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = AggregationJobCreator {
            datastore: ds,
            clock,
            min_aggregation_job_size: MIN_AGGREGATION_JOB_SIZE,
            max_aggregation_job_size: MAX_AGGREGATION_JOB_SIZE,
        };
        job_creator
            .create_aggregation_jobs_for_task(&task)
            .await
            .unwrap();

        // Verify.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(
                    async move { Ok(read_aggregate_jobs_for_task::<Vec<_>, _>(tx, task_id).await) },
                )
            })
            .await
            .unwrap();
        let mut seen_nonces = HashSet::new();
        for (_, nonces) in agg_jobs {
            // All nonces for aggregation job are in the same batch unit.
            let batch_units: HashSet<Time> = nonces
                .iter()
                .map(|nonce| {
                    nonce
                        .time()
                        .to_batch_unit_interval_start(task.min_batch_duration)
                        .unwrap()
                })
                .collect();
            assert_eq!(batch_units.len(), 1);
            let batch_unit = batch_units.into_iter().next().unwrap();

            // The batch is at most MAX_AGGREGATION_JOB_SIZE in size.
            assert!(nonces.len() <= MAX_AGGREGATION_JOB_SIZE);

            // If we are in the current batch unit, the batch is at least MIN_AGGREGATION_JOB_SIZE in size.
            assert!(batch_unit < current_batch_unit || nonces.len() >= MIN_AGGREGATION_JOB_SIZE);

            // Nonces are non-repeated across or inside aggregation jobs.
            for nonce in nonces {
                assert!(!seen_nonces.contains(&nonce));
                seen_nonces.insert(nonce);
            }
        }

        // Every client report was added to some aggregation job.
        assert_eq!(all_nonces, seen_nonces);
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_task_not_enough_reports() {
        // Setup.
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
        let first_report = new_dummy_report(task_id, clock.now());
        let second_report = new_dummy_report(task_id, clock.now());

        ds.run_tx(|tx| {
            let (task, first_report) = (task.clone(), first_report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&first_report).await
            })
        })
        .await
        .unwrap();

        // Run.
        let job_creator = AggregationJobCreator {
            datastore: ds,
            clock,
            min_aggregation_job_size: 2,
            max_aggregation_job_size: 100,
        };
        job_creator
            .create_aggregation_jobs_for_task(&task)
            .await
            .unwrap();

        // Verify -- we haven't received enough reports yet, so we don't create anything.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task::<HashSet<_>, _>(tx, task_id).await)
                })
            })
            .await
            .unwrap();
        assert!(agg_jobs.is_empty());

        // Setup again -- add another report.
        job_creator
            .datastore
            .run_tx(|tx| {
                let second_report = second_report.clone();
                Box::pin(async move { tx.put_client_report(&second_report).await })
            })
            .await
            .unwrap();

        // Run.
        job_creator
            .create_aggregation_jobs_for_task(&task)
            .await
            .unwrap();

        // Verify -- the additional report we wrote allows an aggregation job to be created.
        let agg_jobs = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    Ok(read_aggregate_jobs_for_task::<HashSet<_>, _>(tx, task_id).await)
                })
            })
            .await
            .unwrap();
        assert_eq!(agg_jobs.len(), 1);
        let nonces = agg_jobs.into_iter().next().unwrap().1;
        assert_eq!(
            nonces,
            HashSet::from([first_report.nonce(), second_report.nonce()])
        );
    }

    // Test helper function that reads all aggregation jobs for a given task ID, returning a map
    // from aggregation job ID to the report nonces included in the aggregation job. The container
    // used to store the nonces is up to the caller; ordered containers will store nonces in the
    // order they are included in the aggregate job.
    async fn read_aggregate_jobs_for_task<T: FromIterator<Nonce>, C: Clock>(
        tx: &Transaction<'_, C>,
        task_id: TaskId,
    ) -> HashMap<AggregationJobId, T> {
        // For this test, all of the report aggregations will be in the Start state, so the verify
        // parameter effectively does not matter.
        let verify_param = Prio3Aes128Count::new(2)
            .unwrap()
            .setup()
            .unwrap()
            .1
            .remove(0);

        try_join_all(
            tx.get_aggregation_jobs_for_task_id::<Prio3Aes128Count>(task_id)
                .await
                .unwrap()
                .into_iter()
                .map(|agg_job| {
                    tx.get_report_aggregations_for_aggregation_job::<Prio3Aes128Count>(
                        &verify_param,
                        task_id,
                        agg_job.aggregation_job_id,
                    )
                    .map_ok(move |report_aggs| (agg_job.aggregation_job_id, report_aggs))
                }),
        )
        .await
        .unwrap()
        .into_iter()
        .map(|(agg_job_id, report_aggs)| {
            (
                agg_job_id,
                report_aggs.into_iter().map(|ra| ra.nonce).collect::<T>(),
            )
        })
        .collect()
    }
}
