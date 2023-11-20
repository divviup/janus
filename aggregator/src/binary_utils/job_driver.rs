//! Discovery and driving of jobs scheduled elsewhere.

use anyhow::Context as _;
use chrono::NaiveDateTime;
use janus_aggregator_core::datastore::{self, models::Lease};
use janus_core::{time::Clock, Runtime};
use opentelemetry::{
    metrics::{Meter, Unit},
    KeyValue,
};
use rand::{thread_rng, Rng};
use std::{
    fmt::{Debug, Display},
    future::Future,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Semaphore, SemaphorePermit},
    time::{self, Instant},
};
use tracing::{debug, error, info_span, Instrument};
use trillium_tokio::Stopper;

/// Periodically seeks incomplete jobs in the datastore and drives them concurrently.
pub struct JobDriver<C: Clock, R, JobAcquirer, JobStepper> {
    /// Clock used to determine when to schedule jobs.
    clock: C,
    /// Runtime object used to spawn asynchronous tasks.
    runtime: R,
    /// Meter used to process metric values.
    meter: Meter,
    /// Stopper to signal when to shut down the job driver.
    stopper: Stopper,

    // Configuration values.
    /// The amount of time to wait between job acquisition attempts.
    job_discovery_interval: Duration,
    /// How many jobs to step at the same time in this process.
    max_concurrent_job_workers: usize,
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
        R,
        JobStepperError,
        JobAcquirer,
        JobAcquirerFuture,
        JobStepper,
        JobStepperFuture,
        AcquiredJob,
    > JobDriver<C, R, JobAcquirer, JobStepper>
where
    C: Clock,
    R: Runtime + Send + Sync + 'static,
    JobStepperError: Debug + Display + Send + Sync + 'static,
    JobAcquirer: Fn(usize) -> JobAcquirerFuture + Send + Sync + 'static,
    JobAcquirerFuture: Future<Output = Result<Vec<Lease<AcquiredJob>>, datastore::Error>> + Send,
    JobStepper: Fn(Lease<AcquiredJob>) -> JobStepperFuture + Send + Sync + 'static,
    JobStepperFuture: Future<Output = Result<(), JobStepperError>> + Send,
    AcquiredJob: Clone + Debug + Send + Sync + 'static,
{
    /// Create a new [`JobDriver`].
    pub fn new(
        clock: C,
        runtime: R,
        meter: Meter,
        stopper: Stopper,
        job_discovery_interval: Duration,
        max_concurrent_job_workers: usize,
        worker_lease_clock_skew_allowance: Duration,
        incomplete_job_acquirer: JobAcquirer,
        job_stepper: JobStepper,
    ) -> anyhow::Result<Self> {
        u32::try_from(max_concurrent_job_workers)
            .context("max_concurrent_job_workers was too large")?;
        Ok(Self {
            clock,
            runtime,
            meter,
            stopper,
            job_discovery_interval,
            max_concurrent_job_workers,
            worker_lease_clock_skew_allowance,
            incomplete_job_acquirer,
            job_stepper,
        })
    }

    /// Run this job driver, periodically seeking incomplete jobs and stepping them.
    pub async fn run(self: Arc<Self>) {
        // Create metric recorders.
        let job_acquire_time_histogram = self
            .meter
            .f64_histogram("janus_job_acquire_time")
            .with_description("Time spent acquiring jobs.")
            .with_unit(Unit::new("s"))
            .init();
        let job_step_time_histogram = self
            .meter
            .f64_histogram("janus_job_step_time")
            .with_description("Time spent stepping jobs.")
            .with_unit(Unit::new("s"))
            .init();

        // Set up state for the job driver run.
        let sem = Arc::new(Semaphore::new(self.max_concurrent_job_workers));

        let mut next_run_instant = Instant::now();
        if !self.job_discovery_interval.is_zero() {
            next_run_instant += thread_rng().gen_range(Duration::ZERO..self.job_discovery_interval);
        }

        loop {
            // Wait out our job discovery delay, if any.
            if self
                .stopper
                .stop_future(time::sleep_until(next_run_instant))
                .await
                .is_none()
            {
                // Shut down when signalled via the stopper. Wait for all in-flight jobs to
                // complete by acquiring all semaphore permits.
                //
                // Unwrap safety: The constructor checks that max_concurrent_job_workers can be
                // converted to a u32.
                // Unwrap safety: Semaphore::acquire is documented as only returning an error if the
                // semaphore is closed, and we never close this semaphore.
                let _: SemaphorePermit<'_> = sem
                    .acquire_many(u32::try_from(self.max_concurrent_job_workers).unwrap())
                    .await
                    .unwrap();
                break;
            }

            // Wait until we are able to start at least one worker. (permit will be immediately released)
            //
            // Unwrap safety: Semaphore::acquire is documented as only returning an error if the
            // semaphore is closed, and we never close this semaphore.
            drop(sem.acquire().await.unwrap());

            // Acquire some jobs which are ready to be stepped.
            //
            // We determine the maximum number of jobs to acquire based on the number of semaphore
            // permits available, since we'd like to start processing any acquired jobs immediately
            // to avoid potentially timing out while waiting on _other_ jobs to finish being
            // stepped. This is racy given that workers may complete (and relinquish their permits)
            // concurrently with us acquiring jobs; but that's OK, since this can only make us
            // underestimate the number of jobs we can acquire, and underestimation is acceptable
            // (we'll pick up any additional jobs on the next iteration of this loop). We can't
            // overestimate since this task is the only place that leases are acquired.
            let max_acquire_count = sem.available_permits();
            let start = Instant::now();
            debug!(%max_acquire_count, "Acquiring jobs");
            let leases = match (self.incomplete_job_acquirer)(max_acquire_count).await {
                Ok(leases) => {
                    job_acquire_time_histogram.record(
                        start.elapsed().as_secs_f64(),
                        &[KeyValue::new("status", "success")],
                    );

                    if leases.is_empty() {
                        debug!("No jobs available");
                        next_run_instant += self.job_discovery_interval;
                        continue;
                    } else {
                        assert!(
                            leases.len() <= max_acquire_count,
                            "Acquired {} jobs exceeding maximum of {}",
                            leases.len(),
                            max_acquire_count
                        );
                        debug!(acquired_job_count = leases.len(), "Acquired jobs");
                        next_run_instant = Instant::now();
                        leases
                    }
                }
                Err(error) => {
                    job_acquire_time_histogram.record(
                        start.elapsed().as_secs_f64(),
                        &[KeyValue::new("status", "error")],
                    );

                    // Go ahead and provide a delay in this error case to ensure we don't tightly loop
                    // running transactions that will fail without any delay.
                    next_run_instant += self.job_discovery_interval;
                    error!(?error, "Couldn't acquire jobs");
                    continue;
                }
            };

            // Start up tasks for each acquired job.
            for lease in leases {
                self.runtime.spawn({
                    // We acquire a semaphore in the job-discovery task rather than inside the new
                    // job-stepper task to ensure that acquiring a permit does not race with
                    // checking how many permits we have available in the next iteration of this
                    // loop, to maintain the invariant that this task is the only place we acquire
                    // permits.
                    //
                    // Unwrap safety: we have seen that at least `leases.len()` permits are
                    // available, and this task is the only task that acquires permits.
                    let span = info_span!("Job stepper", acquired_job = ?lease.leased());
                    let (this, permit, job_step_time_histogram) = (
                        Arc::clone(&self),
                        Arc::clone(&sem).try_acquire_owned().unwrap(),
                        job_step_time_histogram.clone(),
                    );

                    async move {
                        debug!(lease_expiry = %lease.lease_expiry_time(), "Stepping job");
                        let (start, mut status) = (Instant::now(), "success");
                        match time::timeout(
                            this.effective_lease_duration(lease.lease_expiry_time()),
                            (this.job_stepper)(lease),
                        )
                        .await
                        {
                            Ok(Ok(_)) => debug!("Job stepped"),
                            Ok(Err(error)) => {
                                error!(?error, "Couldn't step job");
                                status = "error"
                            }
                            Err(_err) => {
                                error!("Stepping job timed out");
                                status = "error"
                            }
                        }
                        job_step_time_histogram.record(
                            start.elapsed().as_secs_f64(),
                            &[KeyValue::new("status", status)],
                        );
                        drop(permit);
                    }
                    .instrument(span)
                });
            }
        }
    }

    fn effective_lease_duration(&self, lease_expiry: &NaiveDateTime) -> Duration {
        // Lease expiries are expressed as Time values (i.e. an absolute timestamp). Tokio Instant
        // values, unfortunately, can't be created directly from a timestamp. All we can do is
        // create an Instant::now(), then add durations to it. This function computes how long
        // remains until the expiry time, minus the clock skew allowance. All math saturates, since
        // we want to timeout immediately if any of these subtractions would underflow.
        Duration::from_secs(
            u64::try_from(lease_expiry.timestamp())
                .unwrap_or_default()
                .saturating_sub(self.clock.now().as_seconds_since_epoch())
                .saturating_sub(self.worker_lease_clock_skew_allowance.as_secs()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::JobDriver;
    use chrono::NaiveDateTime;
    use janus_aggregator_core::{
        datastore::{self, models::Lease},
        test_util::noop_meter,
    };
    use janus_core::{
        test_util::{install_test_trace_subscriber, runtime::TestRuntimeManager},
        time::MockClock,
        vdaf::VdafInstance,
        Runtime,
    };
    use janus_messages::{AggregationJobId, TaskId};
    use rand::random;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Mutex;
    use trillium_tokio::Stopper;

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
        let mut runtime_manager = TestRuntimeManager::new();
        let stopper = Stopper::new();

        /// A fake incomplete job returned by the job acquirer closure.
        #[derive(Clone, Debug)]
        struct IncompleteJob {
            task_id: TaskId,
            job_id: AggregationJobId,
            lease_expiry: NaiveDateTime,
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

        let test_state = Arc::new(Mutex::new(TestState {
            job_acquire_counter: 0,
            stepped_jobs: Vec::new(),
        }));
        // View of incomplete jobs acquired from datastore fed to job finder closure
        let incomplete_jobs = Arc::new(Vec::from([
            // First job finder call: acquire some jobs.
            Vec::from([
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(100, 0).unwrap(),
                },
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(200, 0).unwrap(),
                },
            ]),
            // Second job finder call will be immediately after the first: no more jobs
            // available yet. Should cause a minimum delay before job finder runs again.
            Vec::new(),
            // Third job finder call: return some new jobs to simulate lease being released and
            // re-acquired (it doesn't matter if the task and job IDs change).
            Vec::from([
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(300, 0).unwrap(),
                },
                IncompleteJob {
                    task_id: random(),
                    job_id: random(),
                    lease_expiry: NaiveDateTime::from_timestamp_opt(400, 0).unwrap(),
                },
            ]),
        ]));

        // Run. Let the aggregation job driver step aggregation jobs, then kill it.
        let job_driver = Arc::new(
            JobDriver::new(
                clock,
                runtime_manager.with_label("stepper"),
                noop_meter(),
                stopper.clone(),
                Duration::from_secs(1),
                10,
                Duration::from_secs(60),
                {
                    let (test_state, incomplete_jobs) =
                        (Arc::clone(&test_state), Arc::clone(&incomplete_jobs));
                    move |max_acquire_count| {
                        let (test_state, incomplete_jobs) =
                            (Arc::clone(&test_state), Arc::clone(&incomplete_jobs));
                        async move {
                            let mut test_state = test_state.lock().await;

                            assert_eq!(max_acquire_count, 10);

                            let incomplete_jobs = incomplete_jobs
                                .get(test_state.job_acquire_counter)
                                // Clone here so that incomplete_jobs will be Vec<_> and not &Vec<_>, which
                                // would be impossible to return from Option::unwrap_or_default.
                                .cloned()
                                .unwrap_or_default();

                            let leases = incomplete_jobs
                                .iter()
                                .map(|job| {
                                    Lease::new_dummy(
                                        (job.task_id, VdafInstance::Fake, job.job_id),
                                        job.lease_expiry,
                                    )
                                })
                                .collect();

                            test_state.job_acquire_counter += 1;

                            // Create some fake incomplete jobs
                            Ok(leases)
                        }
                    }
                },
                {
                    let test_state = Arc::clone(&test_state);
                    move |lease| {
                        let test_state = Arc::clone(&test_state);
                        async move {
                            let mut test_state = test_state.lock().await;
                            let job_acquire_counter = test_state.job_acquire_counter;

                            assert_eq!(lease.leased().1, VdafInstance::Fake);

                            test_state.stepped_jobs.push(SteppedJob {
                                observed_jobs_acquire_counter: job_acquire_counter,
                                task_id: lease.leased().0,
                                job_id: lease.leased().2,
                            });

                            Ok(()) as Result<(), datastore::Error>
                        }
                    }
                },
            )
            .unwrap(),
        );
        let task_handle = runtime_manager.with_label("driver").spawn(job_driver.run());

        // Wait for all of the job stepper tasks to be started and for them to finish.
        runtime_manager.wait_for_completed_tasks("stepper", 4).await;
        // Stop the job driver.
        stopper.stop();
        // Wait for the job driver task to complete.
        task_handle.await.unwrap();

        // Verify that we got the expected calls to closures.
        let final_test_state = test_state.lock().await;

        // We expect the job acquirer to run at least three times in the time
        // it takes to step the four jobs, but we can't prove it won't run
        // once more.
        assert!(final_test_state.job_acquire_counter >= 3);
        assert_eq!(
            final_test_state.stepped_jobs,
            Vec::from([
                // First acquirer run should have caused INCOMPLETE_JOBS[0] to be stepped.
                SteppedJob {
                    observed_jobs_acquire_counter: 1,
                    task_id: incomplete_jobs[0][0].task_id,
                    job_id: incomplete_jobs[0][0].job_id,
                },
                SteppedJob {
                    observed_jobs_acquire_counter: 1,
                    task_id: incomplete_jobs[0][1].task_id,
                    job_id: incomplete_jobs[0][1].job_id,
                },
                // Second acquirer run should step no jobs
                // Third acquirer run should have caused INCOMPLETE_JOBS[2] to be stepped.
                SteppedJob {
                    observed_jobs_acquire_counter: 3,
                    task_id: incomplete_jobs[2][0].task_id,
                    job_id: incomplete_jobs[2][0].job_id,
                },
                SteppedJob {
                    observed_jobs_acquire_counter: 3,
                    task_id: incomplete_jobs[2][1].task_id,
                    job_id: incomplete_jobs[2][1].job_id,
                },
            ])
        );
    }
}
