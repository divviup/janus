use anyhow::Context;
use futures::future::try_join_all;
use itertools::Itertools;
use janus_server::binary_utils::datastore;
use janus_server::config::AggregationJobCreatorConfig;
use janus_server::datastore::models::{
    AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
};
use janus_server::datastore::{self, Datastore};
use janus_server::message::{AggregationJobId, Nonce, Role, TaskId, Time};
use janus_server::task::Task;
use janus_server::time::{Clock, RealClock};
use janus_server::trace::install_trace_subscriber;
use prio::codec::Encode;
use prio::vdaf;
use prio::vdaf::prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::fmt::Formatter;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, fmt::Debug, fs};
use structopt::StructOpt;
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio::time::{Instant, MissedTickBehavior};
use tokio::{select, time};
use tracing::{debug, error, info};

#[derive(StructOpt)]
#[structopt(
    name = "janus-aggregation-job-creator",
    about = "Janus aggregation job creator",
    rename_all = "kebab-case",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Options {
    /// Path to configuration YAML.
    #[structopt(
        long,
        env = "CONFIG_FILE",
        parse(from_os_str),
        takes_value = true,
        required(true),
        help = "path to configuration file"
    )]
    config_file: PathBuf,

    /// Password for the PostgreSQL database connection. If specified, must not be specified in the
    /// connection string.
    #[structopt(long, env = "PGPASSWORD", help = "PostgreSQL password")]
    database_password: Option<String>,

    /// Datastore encryption keys.
    #[structopt(
        long,
        env = "DATASTORE_KEYS",
        takes_value = true,
        use_delimiter = true,
        required(true),
        help = "datastore encryption keys, encoded in base64 then comma-separated"
    )]
    datastore_keys: Vec<String>,
}

impl Debug for Options {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("config_file", &self.config_file)
            .finish()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Read arguments, read & parse config.
    let options = Options::from_args();
    let config: AggregationJobCreatorConfig = {
        let config_content = fs::read_to_string(&options.config_file)
            .with_context(|| format!("couldn't read config file {:?}", options.config_file))?;
        serde_yaml::from_str(&config_content)
            .with_context(|| format!("couldn't parse config file {:?}", options.config_file))?
    };
    install_trace_subscriber(&config.logging_config)
        .context("couldn't install tracing subscriber")?;

    info!(?options, ?config, "Starting aggregation job creator");

    // Connect to database.
    let datastore = datastore(
        config.database,
        options.database_password,
        options.datastore_keys,
    )
    .context("couldn't connect to database")?;

    // Start creating aggregation jobs.
    Arc::new(AggregationJobCreator {
        datastore,
        clock: RealClock {},
        tasks_update_frequency: Duration::from_secs(config.tasks_update_frequency_secs),
        aggregation_job_creation_interval: Duration::from_secs(
            config.aggregation_job_creation_interval_secs,
        ),
        min_aggregation_job_size: config.min_aggregation_job_size,
        max_aggregation_job_size: config.max_aggregation_job_size,
    })
    .run()
    .await
}

struct AggregationJobCreator<C: Clock>
where
    C: 'static,
{
    // Dependencies.
    datastore: Datastore,
    clock: C,

    // Configuration values.
    /// How frequently we look for new tasks to start creating aggregation jobs for.
    tasks_update_frequency: Duration,
    /// How frequently we attempt to create new aggregation jobs for each task.
    aggregation_job_creation_interval: Duration,
    /// The minimum number of client reports to include in an aggregation job. Applies to the
    /// "current" batch unit only; historical batch units will create aggregation jobs of any size,
    /// on the theory that almost all reports will have be received for these batch units already.
    min_aggregation_job_size: usize,
    /// The maximum number of client reports to include in an aggregation job.
    max_aggregation_job_size: usize,
}

impl<C: Clock> AggregationJobCreator<C> {
    #[tracing::instrument(skip(self))]
    async fn run(self: Arc<Self>) -> ! {
        // TODO(brandon): add support for handling only a subset of tasks in a single job (i.e. sharding).

        // Set up an interval to occasionally update our view of tasks in the DB.
        // (This will fire immediately, so we'll immediately load tasks from the DB when we enter
        // the loop.)
        let mut tasks_update_ticker = time::interval(self.tasks_update_frequency);
        tasks_update_ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // This tracks the "shutdown handle" (i.e. oneshot sender) used to shut down the per-task
        // worker by task ID.
        let mut job_creation_task_shutdown_handles: HashMap<TaskId, Sender<()>> = HashMap::new();

        loop {
            tasks_update_ticker.tick().await;
            info!("Updating tasks");
            let tasks = self
                .datastore
                .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
                .await;
            let tasks = match tasks {
                Ok(tasks) => tasks
                    .into_iter()
                    .filter_map(|task| match task.role {
                        Role::Leader => Some((task.id, task)),
                        _ => None,
                    })
                    .collect::<HashMap<_, _>>(),

                Err(err) => {
                    error!(?err, "Couldn't update tasks");
                    continue;
                }
            };

            // Stop job creation tasks for no-longer-existing tasks.
            job_creation_task_shutdown_handles.retain(|task_id, _| {
                if tasks.contains_key(task_id) {
                    return true;
                }
                // We don't need to send on the channel: dropping the sender is enough to cause the
                // receiver future to resolve with a RecvError, which will trigger shutdown.
                info!(?task_id, "Stopping job creation worker");
                false
            });

            // Start job creation tasks for newly-discovered tasks.
            for (task_id, task) in tasks {
                if job_creation_task_shutdown_handles.contains_key(&task_id) {
                    continue;
                }
                info!(?task_id, "Starting job creation worker");
                let (tx, rx) = oneshot::channel();
                job_creation_task_shutdown_handles.insert(task_id, tx);
                tokio::task::spawn({
                    let this = self.clone();
                    async move { this.run_for_task(rx, task).await }
                });
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn run_for_task(&self, mut shutdown: Receiver<()>, task: Task) {
        debug!(task_id = ?task.id, "Job creation worker started");
        let first_tick_instant = Instant::now()
            + Duration::from_secs(
                thread_rng().gen_range(0..self.aggregation_job_creation_interval.as_secs()),
            );
        let mut aggregation_job_creation_ticker =
            time::interval_at(first_tick_instant, self.aggregation_job_creation_interval);

        loop {
            select! {
                _ = aggregation_job_creation_ticker.tick() => {
                    info!(task_id = ?task.id, "Creating aggregation jobs for task");
                    if let Err(err) = self.create_aggregation_jobs_for_task(&task).await {
                        error!(task_id = ?task.id, ?err, "Couldn't create aggregation jobs for task")
                    }
                }

                _ = &mut shutdown => {
                    debug!(task_id = ?task.id, "Job creation worker stopped");
                    return;
                }
            }
        }
    }

    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task(&self, task: &Task) -> anyhow::Result<()> {
        match task.vdaf {
            janus_server::task::Vdaf::Prio3Aes128Count => {
                self.create_aggregation_jobs_for_task_no_param::<Prio3Aes128Count>(task)
                    .await
            }

            janus_server::task::Vdaf::Prio3Aes128Sum { .. } => {
                self.create_aggregation_jobs_for_task_no_param::<Prio3Aes128Sum>(task)
                    .await
            }

            janus_server::task::Vdaf::Prio3Aes128Histogram { .. } => {
                self.create_aggregation_jobs_for_task_no_param::<Prio3Aes128Histogram>(task)
                    .await
            }

            _ => panic!("VDAF {:?} is not yet supported", task.vdaf),
        }
    }

    #[tracing::instrument(skip(self), err)]
    async fn create_aggregation_jobs_for_task_no_param<A: vdaf::Aggregator<AggregationParam = ()>>(
        &self,
        task: &Task,
    ) -> anyhow::Result<()>
    where
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
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
                                .time
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
    use chrono::NaiveDateTime;
    use futures::{future::try_join_all, TryFutureExt};
    use janus_server::{
        datastore::{Crypter, Datastore, Transaction},
        message::{
            test_util::new_dummy_report, AggregationJobId, Nonce, Report, Role, TaskId, Time,
        },
        task::{test_util::new_dummy_task, Vdaf},
        time::{test_util::MockClock, Clock},
        trace::test_util::install_test_trace_subscriber,
    };
    use prio::vdaf::{prio3::Prio3Aes128Count, Vdaf as _};
    use std::{
        collections::{HashMap, HashSet},
        iter,
        sync::Arc,
        time::Duration,
    };
    use tokio::{task, time};

    test_util::define_ephemeral_datastore!();

    #[tokio::test]
    async fn aggregation_job_creator() {
        // This is a minimal test that AggregationJobCreator::run() will successfully find tasks &
        // trigger creation of aggregation jobs. More detailed tests of the aggregation job creation
        // logic are contained in other tests which do not exercise the task-lookup code.

        // Setup.
        install_test_trace_subscriber();
        let (ds, _db_handle) = ephemeral_datastore().await;

        // TODO(brandon): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing this TODO, calling time::pause() breaks interaction
        // with the database -- the task-loader transaction deadlocks on attempting to start a
        // transaction, even if the main test loops on calling yield_now().

        let report_time = Time::from_naive_date_time(NaiveDateTime::from_timestamp(0, 0));

        let leader_task_id = TaskId::random();
        let leader_task = new_dummy_task(leader_task_id, Vdaf::Prio3Aes128Count, Role::Leader);
        let leader_report = new_dummy_report(leader_task_id, report_time);

        let helper_task_id = TaskId::random();
        let helper_task = new_dummy_task(helper_task_id, Vdaf::Prio3Aes128Count, Role::Helper);
        let helper_report = new_dummy_report(helper_task_id, report_time);

        ds.run_tx(|tx| {
            let (leader_task, helper_task) = (leader_task.clone(), helper_task.clone());
            let (leader_report, helper_report) = (leader_report.clone(), helper_report.clone());
            Box::pin(async move {
                tx.put_task(&leader_task).await?;
                tx.put_task(&helper_task).await?;

                tx.put_client_report(&leader_report).await?;
                tx.put_client_report(&helper_report).await
            })
        })
        .await
        .unwrap();

        // Create & run the aggregation job creator, give it long enough to create tasks, and then
        // kill it.
        const AGGREGATION_JOB_CREATION_INTERVAL: Duration = Duration::from_secs(1);
        let job_creator = Arc::new(AggregationJobCreator {
            datastore: ds,
            clock: MockClock::default(),
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: AGGREGATION_JOB_CREATION_INTERVAL,
            min_aggregation_job_size: 0,
            max_aggregation_job_size: 100,
        });
        let task_handle = task::spawn({
            let job_creator = job_creator.clone();
            async move { job_creator.run().await }
        });
        time::sleep(5 * AGGREGATION_JOB_CREATION_INTERVAL).await;
        task_handle.abort();

        // Inspect database state to verify that the expected aggregation jobs were created.
        let (leader_agg_jobs, helper_agg_jobs) = job_creator
            .datastore
            .run_tx(|tx| {
                Box::pin(async move {
                    let leader_agg_jobs =
                        read_aggregate_jobs_for_task::<HashSet<_>>(tx, leader_task_id).await;
                    let helper_agg_jobs =
                        read_aggregate_jobs_for_task::<HashSet<_>>(tx, helper_task_id).await;
                    Ok((leader_agg_jobs, helper_agg_jobs))
                })
            })
            .await
            .unwrap();
        assert!(helper_agg_jobs.is_empty());
        assert_eq!(leader_agg_jobs.len(), 1);
        let nonces = leader_agg_jobs.into_iter().next().unwrap().1;
        assert_eq!(nonces, HashSet::from([leader_report.nonce]));
    }

    #[tokio::test]
    async fn create_aggregation_jobs_for_task() {
        // Setup.
        let (ds, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

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
        let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Leader);
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
            .map(|report| report.nonce)
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
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
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
                    async move { Ok(read_aggregate_jobs_for_task::<Vec<_>>(tx, task_id).await) },
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
                        .time
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
        let (ds, _db_handle) = ephemeral_datastore().await;
        let clock = MockClock::default();

        let task_id = TaskId::random();
        let task = new_dummy_task(task_id, Vdaf::Prio3Aes128Count, Role::Leader);
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
            tasks_update_frequency: Duration::from_secs(3600),
            aggregation_job_creation_interval: Duration::from_secs(1),
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
                    Ok(read_aggregate_jobs_for_task::<HashSet<_>>(tx, task_id).await)
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
                    Ok(read_aggregate_jobs_for_task::<HashSet<_>>(tx, task_id).await)
                })
            })
            .await
            .unwrap();
        assert_eq!(agg_jobs.len(), 1);
        let nonces = agg_jobs.into_iter().next().unwrap().1;
        assert_eq!(
            nonces,
            HashSet::from([first_report.nonce, second_report.nonce])
        );
    }

    // Test helper function that reads all aggregation jobs for a given task ID, returning a map
    // from aggregation job ID to the report nonces included in the aggregation job. The container
    // used to store the nonces is up to the caller; ordered containers will store nonces in the
    // order they are included in the aggregate job.
    async fn read_aggregate_jobs_for_task<T: FromIterator<Nonce>>(
        tx: &Transaction<'_>,
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
