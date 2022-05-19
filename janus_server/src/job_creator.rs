//! Creation of per-task jobs.

use crate::{config::JobCreatorConfig, datastore::Datastore, task::Task};
use janus::{
    message::{Role, TaskId},
    time::Clock,
};
use rand::{thread_rng, Rng};
use std::{collections::HashMap, future::Future, sync::Arc, time::Duration};
use tokio::{
    select,
    sync::oneshot::{self, Receiver, Sender},
    time::{self, Instant, MissedTickBehavior},
};
use tracing::{debug, error, info};

/// Periodically invokes a job creator callback for each task discovered in the datastore.
pub struct PerTaskJobCreator<C: Clock, F> {
    // Dependencies.
    /// Datastore from which tasks are discovered and which is provided to `job_creator`.
    datastore: Arc<Datastore<C>>,
    /// Clock used to determine when to schedule jobs.
    clock: C,

    // Configuration values.
    /// How frequently we look for new tasks to start creating aggregation jobs for.
    tasks_update_frequency: Duration,
    /// How frequently we attempt to create new jobs for each task.
    job_creation_interval: Duration,
    /// The job creator function.
    job_creator: F,
}

impl<C, F, Fut> PerTaskJobCreator<C, F>
where
    C: Clock,
    F: Fn(C, Arc<Datastore<C>>, Task) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send,
{
    /// Create a new [`JobCreator`].
    pub fn new(
        datastore: Arc<Datastore<C>>,
        clock: C,
        config: JobCreatorConfig,
        job_creator: F,
    ) -> Self {
        Self {
            datastore,
            clock,
            tasks_update_frequency: Duration::from_secs(config.tasks_update_frequency_secs),
            job_creation_interval: Duration::from_secs(config.job_creation_interval_secs),
            job_creator,
        }
    }

    /// Run this job creator, periodically invoking the job creator callback for each task.
    #[tracing::instrument(skip(self))]
    pub async fn run(self: Arc<Self>) -> ! {
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
            + Duration::from_secs(thread_rng().gen_range(0..self.job_creation_interval.as_secs()));
        let mut job_creation_ticker =
            time::interval_at(first_tick_instant, self.job_creation_interval);

        loop {
            select! {
                _ = job_creation_ticker.tick() => {
                    info!(task_id = ?task.id, "Creating jobs for task");
                    if let Err(err) = (self.job_creator)(self.clock.clone(), self.datastore.clone(), task.clone()).await {
                        error!(task_id = ?task.id, ?err, "Couldn't create jobs for task")
                    }
                }

                _ = &mut shutdown => {
                    debug!(task_id = ?task.id, "Job creation worker stopped");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::JobCreatorConfig,
        datastore::{Crypter, Datastore},
        task::{test_util::new_dummy_task, VdafInstance},
        trace::test_util::install_test_trace_subscriber,
    };
    use janus::{
        message::{Role, TaskId},
        time::Clock,
    };
    use janus_test_util::MockClock;
    use std::{sync::Arc, time::Duration};
    use tokio::{task, time};

    janus_test_util::define_ephemeral_datastore!();

    #[tokio::test]
    async fn aggregation_job_creator() {
        // This is a minimal test that AggregationJobCreator::run() will successfully find tasks &
        // trigger creation of aggregation jobs. More detailed tests of the aggregation job creation
        // logic are contained in other tests which do not exercise the task-lookup code.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;

        // TODO(brandon): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing this TODO, calling time::pause() breaks interaction
        // with the database -- the task-loader transaction deadlocks on attempting to start a
        // transaction, even if the main test loops on calling yield_now().

        let leader_task_id = TaskId::random();
        let leader_task =
            new_dummy_task(leader_task_id, VdafInstance::Prio3Aes128Count, Role::Leader);

        let helper_task_id = TaskId::random();
        let helper_task =
            new_dummy_task(helper_task_id, VdafInstance::Prio3Aes128Count, Role::Helper);

        let third_task_id = TaskId::random();

        ds.run_tx(|tx| {
            let (leader_task, helper_task) = (leader_task.clone(), helper_task.clone());
            Box::pin(async move {
                tx.put_task(&leader_task).await?;
                tx.put_task(&helper_task).await
            })
        })
        .await
        .unwrap();

        let ds = Arc::new(ds);

        // Create & run the aggregation job creator, give it long enough to create tasks, and then
        // kill it.
        const JOB_CREATION_INTERVAL: Duration = Duration::from_secs(1);
        let job_creator = Arc::new(PerTaskJobCreator::new(
            ds.clone(),
            clock,
            JobCreatorConfig {
                tasks_update_frequency_secs: 3600,
                job_creation_interval_secs: 1,
            },
            move |_clock, datastore, task| async move {
                assert_eq!(task.id, leader_task_id);
                // Write something to the datastore to prove that the right value gets passed in
                datastore
                    .run_tx(|tx| {
                        Box::pin(async move {
                            let new_task = new_dummy_task(
                                third_task_id,
                                VdafInstance::Prio3Aes128Count,
                                Role::Leader,
                            );
                            tx.put_task(&new_task).await
                        })
                    })
                    .await
                    .unwrap();

                Ok(())
            },
        ));
        let task_handle = task::spawn({
            let job_creator = job_creator.clone();
            async move { job_creator.run().await }
        });
        time::sleep(5 * JOB_CREATION_INTERVAL).await;
        task_handle.abort();

        // Inspect database state to verify that the expected dummy task was written.
        ds.run_tx(|tx| {
            Box::pin(async move {
                tx.get_task(third_task_id).await.unwrap().unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();
    }
}
