//! Discovery and driving of jobs scheduled elsewhere.

use crate::datastore::{self, Datastore};
use janus::{
    message::{Duration, Time},
    time::Clock,
};
use std::{fmt::Debug, future::Future, sync::Arc};
use tokio::{sync::Semaphore, task, time};
use tracing::{debug, error, info, info_span, Instrument};

/// Periodically seeks incomplete jobs in the datastore and drives them concurrently.
pub struct JobDriver<C: Clock, JobAcquirer, JobStepper> {
    /// Datastore where incomplete jobs are discovered and which is provided to the job driver.
    datastore: Arc<Datastore<C>>,
    /// Clock used to determine when to schedule jobs.
    clock: C,

    // Configuration values.
    /// Minimum delay between datastore job discovery passes.
    min_job_discovery_delay: Duration,
    /// Maximum delay between datastore job discovery passes.
    max_job_discovery_delay: Duration,
    /// How many jobs to step at the same time in this process.
    max_concurrent_job_workers: usize,
    /// How long a lease on a job lasts.
    worker_lease_duration: Duration,
    /// Allowable clock skew between datastore and job driver, used when determining if a lease has
    /// expired.
    worker_lease_clock_skew_allowance: Duration,

    // Callbacks.
    /// Finds incomplete jobs in the datastore and acquires a lease on them.
    incomplete_job_acquirer: JobAcquirer,
    /// Steps an incomplete job.
    job_stepper: JobStepper,
}

impl<
        C,
        JobStepperError,
        JobAcquirer,
        JobAcquirerFuture,
        JobStepper,
        JobStepperFuture,
        AcquiredJob,
    > JobDriver<C, JobAcquirer, JobStepper>
where
    C: Clock,
    JobStepperError: Debug + Send + Sync + 'static,
    JobAcquirer:
        Fn(Arc<Datastore<C>>, Duration, usize) -> JobAcquirerFuture + Send + Sync + 'static,
    JobAcquirerFuture: Future<Output = Result<Vec<(AcquiredJob, Time)>, datastore::Error>> + Send,
    JobStepper: Fn(Arc<Datastore<C>>, AcquiredJob) -> JobStepperFuture + Send + Sync + 'static,
    JobStepperFuture: Future<Output = Result<(), JobStepperError>> + Send,
    AcquiredJob: Clone + Debug + Send + Sync + 'static,
{
    /// Create a new [`JobCreator`].
    pub fn new(
        datastore: Arc<Datastore<C>>,
        clock: C,
        min_job_discovery_delay: Duration,
        max_job_discovery_delay: Duration,
        max_concurrent_job_workers: usize,
        worker_lease_duration: Duration,
        worker_lease_clock_skew_allowance: Duration,
        incomplete_job_acquirer: JobAcquirer,
        job_stepper: JobStepper,
    ) -> Self {
        Self {
            datastore,
            clock,
            min_job_discovery_delay,
            max_job_discovery_delay,
            max_concurrent_job_workers,
            worker_lease_duration,
            worker_lease_clock_skew_allowance,
            incomplete_job_acquirer,
            job_stepper,
        }
    }

    /// Run this job driver, periodically seeking incomplete jobs and stepping them.
    #[tracing::instrument(skip(self))]
    pub async fn run(self: Arc<Self>) -> ! {
        let sem = Arc::new(Semaphore::new(self.max_concurrent_job_workers));
        let mut job_discovery_delay = Duration::ZERO;

        loop {
            // Wait out our job discovery delay, if any.
            time::sleep(time::Duration::from_secs(job_discovery_delay.as_seconds())).await;

            // Wait until we are able to start at least one worker. (permit will be immediately released)
            //
            // Unwrap safety: Semaphore::acquire is documented as only returning an error if the
            // semaphore is closed, and we never close this semaphore.
            let _ = sem.acquire().await.unwrap();

            // Acquire some jobs which are ready to be stepped.
            //
            // We determine the maximum number of jobs to acquire based on the number of semaphore
            // permits available, since we'd like to start processing any acquired jobs immediately
            // to avoid potentially timing out while waiting on _other_ jobs to finish being
            // stepped. This is racy given that workers may complete (and relinquish their permits)
            // concurrently with us acquiring jobs; but that's OK, since this can only make us
            // underestimate the number of jobs we can acquire, and underestimation is acceptable
            // (we'll pick up any additional jobs on the next iteration of this loop). We can't
            // overestimate since this task is the only place that permits are acquired.

            // TODO(brandon): only acquire jobs whose batch units have not already been collected (probably by modifying acquire_incomplete_aggregation_jobs)
            let max_acquire_count = sem.available_permits();
            info!(max_acquire_count, "Acquiring jobs");
            let acquired_jobs = (self.incomplete_job_acquirer)(
                Arc::clone(&self.datastore),
                self.worker_lease_duration,
                max_acquire_count,
            )
            .await;
            let acquired_jobs = match acquired_jobs {
                Ok(acquired_jobs) => acquired_jobs,
                Err(err) => {
                    error!(?err, "Couldn't acquire jobs");
                    // Go ahead and step job discovery delay in this error case to ensure we don't
                    // tightly loop running transactions that will fail without any delay.
                    job_discovery_delay = self.step_job_discovery_delay(job_discovery_delay);
                    continue;
                }
            };
            if acquired_jobs.is_empty() {
                debug!("No jobs available");
                job_discovery_delay = self.step_job_discovery_delay(job_discovery_delay);
                continue;
            }
            assert!(
                acquired_jobs.len() <= max_acquire_count,
                "Acquired {} jobs exceeding maximum of {}",
                acquired_jobs.len(),
                max_acquire_count
            );
            info!(acquired_job_count = acquired_jobs.len(), "Acquired jobs");

            // Start up tasks for each acquired job.
            job_discovery_delay = Duration::ZERO;
            for (acquired_job, lease_expiry) in acquired_jobs {
                task::spawn({
                    // We acquire a semaphore in the job-discovery task rather than inside the new
                    // job-stepper task to ensure that acquiring a permit does not race with
                    // checking how many permits we have available in the next iteration of this
                    // loop, to maintain the invariant that this task is the only place we acquire
                    // permits.
                    //
                    // Unwrap safety: we have seen that at least `acquired_jobs.len()` permits are
                    // available, and this task is the only task that acquires permits.
                    let permit = Arc::clone(&sem).try_acquire_owned().unwrap();
                    let this = Arc::clone(&self);
                    let span = info_span!("Job stepper", ?acquired_job);

                    async move {
                        info!(?lease_expiry, "Stepping job");
                        match time::timeout(
                            this.effective_lease_duration(lease_expiry),
                            (this.job_stepper)(Arc::clone(&this.datastore), acquired_job),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                debug!("Job stepped")
                            }

                            Ok(Err(err)) => {
                                error!(?err, "Couldn't step job")
                            }

                            Err(err) => error!(?err, "Stepping job timed out"),
                        }
                        drop(permit);
                    }
                    .instrument(span)
                });
            }
        }
    }

    fn step_job_discovery_delay(&self, delay: Duration) -> Duration {
        // A zero delay is stepped to the configured minimum delay.
        if delay == Duration::ZERO {
            return self.min_job_discovery_delay;
        }

        // Nonzero delays are doubled, up to the maximum configured delay.
        // (It's OK to use a saturating multiply here because the following min call causes us to
        // get the right answer even in the case we saturate.)
        let new_delay = Duration::from_seconds(delay.as_seconds().saturating_mul(2));
        let new_delay = Duration::min(new_delay, self.max_job_discovery_delay);
        debug!(%new_delay, "Updating job discovery delay");
        new_delay
    }

    fn effective_lease_duration(&self, lease_expiry: Time) -> time::Duration {
        // Lease expiries are expressed as Time values (i.e. an absolute timestamp). Tokio Instant
        // values, unfortunately, can't be created directly from a timestamp. All we can do is
        // create an Instant::now(), then add durations to it. This function computes how long
        // remains until the expiry time, minus the clock skew allowance. All math saturates, since
        // we want to timeout immediately if any of these subtractions would underflow.
        time::Duration::from_secs(
            lease_expiry
                .as_seconds_since_epoch()
                .saturating_sub(self.clock.now().as_seconds_since_epoch())
                .saturating_sub(self.worker_lease_clock_skew_allowance.as_seconds()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        datastore::{Crypter, Datastore},
        message::AggregationJobId,
        task::VdafInstance,
        trace::test_util::install_test_trace_subscriber,
    };
    use janus::{message::TaskId, time::Clock};
    use janus_test_util::MockClock;
    use lazy_static::lazy_static;
    use tokio::{sync::Mutex, task, time};

    janus_test_util::define_ephemeral_datastore!();

    #[tokio::test]
    async fn job_driver() {
        // This is a minimal test that JobDriver::run() will successfully find jobs & step them to
        // completion. More detailed tests of the job execution logic are contained in other tests
        // which do not exercise the job-acquiry loop.
        // Note that we actually step twice to ensure that lease-release & re-acquiry works as
        // expected.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);

        /// A fake incomplete job returned by the job acquirer closure.
        #[derive(Clone, Debug)]
        struct IncompleteJob {
            task_id: TaskId,
            job_id: AggregationJobId,
            lease_expiry: Time,
        }

        /// Records a job observed by the job stepper closure.
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct SteppedJob {
            observed_jobs_acquire_counter: usize,
            task_id: TaskId,
            job_id: AggregationJobId,
        }

        #[derive(Clone, Debug)]
        struct TestState {
            // Counter incremented when the job finder closure runs and index into INCOMPLETE_JOBS.
            job_acquire_counter: usize,
            stepped_jobs: Vec<SteppedJob>,
        }

        lazy_static! {
            static ref TEST_STATE: Mutex<TestState> = Mutex::const_new(TestState {
                job_acquire_counter: 0,
                stepped_jobs: vec![],
            });
            // View of incomplete jobs acquired from datastore fed to job finder closure
            static ref INCOMPLETE_JOBS: Vec<Vec<IncompleteJob>> = vec![
                // First job finder call: acquire some jobs.
                vec![
                    IncompleteJob {
                     task_id:   TaskId::random(),
                        job_id: AggregationJobId::random(),
                        lease_expiry: Time::from_seconds_since_epoch(100),
                    },
                    IncompleteJob {
                     task_id:   TaskId::random(),
                        job_id: AggregationJobId::random(),
                        lease_expiry: Time::from_seconds_since_epoch(200),
                    },
                ],
                // Second job finder call will be immediately after the first: no more jobs
                // available yet. Should cause a minimum delay before job finder runs again.
                vec![],
                // Third job finder call: return some new jobs to simulate lease being released and
                // re-acquired (it doesn't matter if the task and job IDs change).
                vec![
                    IncompleteJob {
                     task_id:   TaskId::random(),
                        job_id: AggregationJobId::random(),
                        lease_expiry: Time::from_seconds_since_epoch(300),
                    },
                    IncompleteJob {
                     task_id:   TaskId::random(),
                        job_id: AggregationJobId::random(),
                        lease_expiry: Time::from_seconds_since_epoch(400),
                    },
                ],
            ];
        };

        // Run. Give the aggregation job driver enough time to step aggregation jobs, then kill it.
        let job_driver = Arc::new(JobDriver::new(
            ds,
            clock,
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::from_seconds(600),
            Duration::from_seconds(60),
            move |_datastore, lease_duration, max_acquire_count| async move {
                let mut test_state = TEST_STATE.lock().await;

                assert_eq!(lease_duration, Duration::from_seconds(600));
                assert_eq!(max_acquire_count, 10);

                let incomplete_jobs = INCOMPLETE_JOBS
                    .get(test_state.job_acquire_counter)
                    // Clone here so that incomplete_jobs will be Vec<_> and not &Vec<_>, which
                    // would be impossible to return from Option::unwrap_or_default.
                    .cloned()
                    .unwrap_or_default();

                let acquired_jobs = incomplete_jobs
                    .iter()
                    .map(|job| {
                        (
                            (job.task_id, VdafInstance::Fake, job.job_id),
                            job.lease_expiry,
                        )
                    })
                    .collect();

                test_state.job_acquire_counter += 1;

                // Create some fake incomplete jobs
                Ok(acquired_jobs)
            },
            move |_datastore, acquired_job| async move {
                let mut test_state = TEST_STATE.lock().await;
                let job_acquire_counter = test_state.job_acquire_counter;

                assert_eq!(acquired_job.1, VdafInstance::Fake);

                test_state.stepped_jobs.push(SteppedJob {
                    observed_jobs_acquire_counter: job_acquire_counter,
                    task_id: acquired_job.0,
                    job_id: acquired_job.2,
                });

                Ok(()) as Result<(), datastore::Error>
            },
        ));
        let task_handle = task::spawn(async move { job_driver.run().await });

        // TODO(brandon): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing this TODO, calling time::pause() breaks interaction
        // with the database -- the job-acquiry transaction deadlocks on attempting to start a
        // transaction, even if the main test loops on calling yield_now().
        time::sleep(time::Duration::from_secs(5)).await;
        task_handle.abort();

        // Verify that we got the expected calls to closures.
        let final_test_state = TEST_STATE.lock().await;

        // We expect the job acquirer to run at least three times in the 5s we sleep,, but we can't
        // prove it won't run once more.
        assert!(final_test_state.job_acquire_counter >= 3);
        assert_eq!(
            final_test_state.stepped_jobs,
            vec![
                // First acquirer run should have caused INCOMPLETE_JOBS[0] to be stepped.
                SteppedJob {
                    observed_jobs_acquire_counter: 1,
                    task_id: INCOMPLETE_JOBS[0][0].task_id,
                    job_id: INCOMPLETE_JOBS[0][0].job_id,
                },
                SteppedJob {
                    observed_jobs_acquire_counter: 1,
                    task_id: INCOMPLETE_JOBS[0][1].task_id,
                    job_id: INCOMPLETE_JOBS[0][1].job_id,
                },
                // Second acquirer run should step no jobs
                // Third acquirer run should have caused INCOMPLETE_JOBS[2] to be stepped.
                SteppedJob {
                    observed_jobs_acquire_counter: 3,
                    task_id: INCOMPLETE_JOBS[2][0].task_id,
                    job_id: INCOMPLETE_JOBS[2][0].job_id,
                },
                SteppedJob {
                    observed_jobs_acquire_counter: 3,
                    task_id: INCOMPLETE_JOBS[2][1].task_id,
                    job_id: INCOMPLETE_JOBS[2][1].job_id,
                },
            ]
        );
    }
}
