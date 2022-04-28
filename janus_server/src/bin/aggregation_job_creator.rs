use anyhow::{anyhow, Context};
use futures::future::Fuse;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;
use itertools::Itertools;
use janus_server::binary_utils::datastore;
use janus_server::config::AggregationJobCreatorConfig;
use janus_server::datastore::models::{
    AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
};
use janus_server::datastore::{self, Datastore};
use janus_server::message::{AggregationJobId, Nonce, Report, Time};
use janus_server::task::Task;
use janus_server::trace::install_trace_subscriber;
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
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tokio::{select, time};
use tracing::info;

#[derive(StructOpt)]
#[structopt(
    name = "janus-aggregator",
    about = "PPM aggregator server",
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

    /// Password for the PostgreSQL database connection. (if not included in the connection
    /// string)
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

    run_aggregation_job_creator(Arc::new(datastore)).await
}

async fn run_aggregation_job_creator(datastore: Arc<Datastore>) -> anyhow::Result<()> {
    // TODO(brandon): add support for handling only a subset of tasks in a single job (i.e. sharding).

    // XXX: throw all of this away, and just loop finding all tasks -> generate future per task to generate new agg jobs -> joining all futures? *sigh*

    // Set up an interval to occasionally update our view of tasks in the DB.
    // (This will fire immediately, so we'll immediately load tasks from the DB once we enter the
    // select loop.)
    const TASKS_UPDATE_FREQUENCY: Duration = Duration::from_secs(600); // XXX: make configurable
    let mut tasks_update_interval = time::interval(TASKS_UPDATE_FREQUENCY);
    tasks_update_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut job_creation_tasks: HashMap<_, Fuse<JoinHandle<_>>> = HashMap::new();

    loop {
        let mut job_creation_tasks_future: FuturesUnordered<_> =
            job_creation_tasks.values_mut().collect();

        select! {
            // Update set of tasks we are creating aggregation jobs for every now & then.
            _ = tasks_update_interval.tick() => {
                drop(job_creation_tasks_future);
                info!("Updating tasks");
                let tasks = datastore.run_tx(|tx| Box::pin(async move{ tx.get_tasks().await })).await?.into_iter().map(|task| (task.id, task)).collect::<HashMap<_, _>>();

                // Trim job creation tasks for nonexistent tasks.
                job_creation_tasks.retain(|task_id, task| {
                    if !tasks.contains_key(task_id) {
                        info!("Stopping job creation task for task {:?}", task_id);
                        // task.abort(); // XXX: can't abort because wrapped in Fuse, Fuse doesn't let us get a reference to the inner future :-(
                        return false;
                    }
                    return true;
                });

                // Create job creation tasks for new tasks.
                for (task_id, task) in tasks {
                    if job_creation_tasks.contains_key(&task_id) {
                        continue;
                    }
                    info!("Starting job creation task for task {:?}", task_id);
                    job_creation_tasks.insert(task_id, tokio::task::spawn({
                        let datastore = datastore.clone();
                        async move {
                            run_aggregation_job_creator_for_task(datastore, task).await.with_context(|| format!("couldn't create aggregation jobs for task {:?}", task_id))
                        }
                    }).fuse());
                }
            }

            // If one of the single-task job creation tasks finishes, error out if it was in error.
            // XXX: this doesn't quite work. we need to figure out how to remove the finished future
            // from job_creation_tasks in order to avoid polling it again in future iterations of
            // the loop.
            rslt = job_creation_tasks_future.next(), if !job_creation_tasks_future.is_empty() => {
                if let Some(rslt) = rslt {
                    rslt??;
                }
            }
        }
    }
}

async fn run_aggregation_job_creator_for_task(
    datastore: Arc<Datastore>,
    task: Task,
) -> anyhow::Result<()> {
    // Create a ticker to allow us to periodically create new aggregation jobs for the given task.
    // We randomize when in the update period we start in order to avoid a thundering herd problem
    // on startup.
    const TASK_UPDATE_FREQUENCY: Duration = Duration::from_secs(60); // XXX: make configurable
    let first_tick_instant = Instant::now()
        + Duration::from_secs(thread_rng().gen_range(0..=TASK_UPDATE_FREQUENCY.as_secs()));
    let mut task_update_interval = time::interval_at(first_tick_instant, TASK_UPDATE_FREQUENCY);

    loop {
        task_update_interval.tick().await;
        run_aggregation_job_creator_for_task_once(&datastore, &task).await?;
    }
}

async fn run_aggregation_job_creator_for_task_once(
    datastore: &Datastore,
    task: &Task,
) -> anyhow::Result<()> {
    match task.vdaf {
        janus_server::task::Vdaf::Prio3Aes128Count => {
            create_aggregation_jobs_no_param::<Prio3Aes128Count>(datastore, task).await
        }

        janus_server::task::Vdaf::Prio3Aes128Sum { .. } => {
            create_aggregation_jobs_no_param::<Prio3Aes128Sum>(datastore, task).await
        }

        janus_server::task::Vdaf::Prio3Aes128Histogram { .. } => {
            create_aggregation_jobs_no_param::<Prio3Aes128Histogram>(datastore, task).await
        }

        _ => panic!("VDAF {:?} is not yet supported", task.vdaf),
    }
}

async fn create_aggregation_jobs_no_param<A: vdaf::Aggregator>(
    datastore: &Datastore,
    task: &Task,
) -> anyhow::Result<()>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
    A::AggregationParam: Default,
{
    let task_id = task.id;
    let min_batch_duration = task.min_batch_duration;

    // XXX: make configurable
    const MIN_BATCH_SIZE: usize = 100; // only for "current" batch unit
    const MAX_BATCH_SIZE: usize = 1000;

    Ok(datastore
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

                let mut agg_jobs = Vec::new();
                let mut report_aggs = Vec::new();
                for (unit_interval_start, nonces) in nonces_by_batch_unit {
                    for agg_job_nonces in nonces.chunks(MAX_BATCH_SIZE) {
                        // XXX: don't create job if we're in the "current" batch unit & there are too few nonces

                        let aggregation_job_id = AggregationJobId::random();
                        agg_jobs.push(AggregationJob::<A> {
                            aggregation_job_id,
                            task_id,
                            aggregation_param: A::AggregationParam::default(),
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

                // XXX
                Ok(())
            })
        })
        .await?)
}
