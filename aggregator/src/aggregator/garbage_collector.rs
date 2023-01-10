use std::sync::Arc;

use crate::{
    datastore::Datastore,
    messages::TimeExt,
    task::{QueryType, Task},
};
use anyhow::{anyhow, Context, Result};
use futures::future::join_all;
use janus_core::time::Clock;
use janus_messages::Role;
use tracing::error;

pub struct GarbageCollector<C: Clock> {
    // Dependencies.
    datastore: Arc<Datastore<C>>,
    clock: C,
}

impl<C: Clock> GarbageCollector<C> {
    pub fn new(datastore: Arc<Datastore<C>>, clock: C) -> Self {
        Self { datastore, clock }
    }

    #[tracing::instrument(skip(self))]
    pub async fn run(&self) -> Result<()> {
        // TODO(#224): add support for handling only a subset of tasks in a single job (i.e. sharding).

        // Retrieve tasks.
        let tasks = self
            .datastore
            .run_tx(|tx| Box::pin(async move { tx.get_tasks().await }))
            .await
            .context("couldn't retrieve tasks")?;

        // Run GC for each task.
        join_all(tasks.into_iter().map(|task| async move {
            let task = Arc::new(task);
            if let Err(err) = self.gc_task(Arc::clone(&task)).await {
                error!(task_id = ?task.id(), ?err, "Couldn't GC task");
            }
        }))
        .await;
        Ok(())
    }

    async fn gc_task(&self, task: Arc<Task>) -> Result<()> {
        let oldest_allowed_report_timestamp =
            if let Some(report_expiry_age) = task.report_expiry_age() {
                if task.role() != &Role::Leader || task.query_type() != &QueryType::TimeInterval {
                    return Err(anyhow!(
                        "garbage collection is implemented only for leader, time-interval tasks"
                    ));
                }
                self.clock.now().sub(report_expiry_age)?
            } else {
                // No configured report expiry age -- nothing to GC.
                return Ok(());
            };

        self.datastore
            .run_tx(|tx| {
                let task = Arc::clone(&task);
                Box::pin(async move {
                    // Find and delete old collect jobs.
                    tx.delete_old_collect_artifacts(task.id(), oldest_allowed_report_timestamp)
                        .await?;

                    // Find and delete old aggregation jobs/report aggregations/batch aggregations.
                    tx.delete_old_aggregation_artifacts(task.id(), oldest_allowed_report_timestamp)
                        .await?;

                    // Find and delete old client reports.
                    tx.delete_old_client_reports(task.id(), oldest_allowed_report_timestamp)
                        .await?;

                    Ok(())
                })
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::GarbageCollector;
    use crate::{
        datastore::{
            models::{
                AggregationJob, AggregationJobState, CollectJob, CollectJobState,
                LeaderStoredReport, ReportAggregation, ReportAggregationState,
            },
            test_util::ephemeral_datastore,
        },
        messages::TimeExt,
        task::{self, test_util::TaskBuilder},
    };
    use janus_core::{
        task::VdafInstance,
        test_util::{
            dummy_vdaf::{self, AggregationParam},
            install_test_trace_subscriber,
        },
        time::{Clock, MockClock},
    };
    use janus_messages::{query_type::TimeInterval, Duration, Interval, Role, Time};
    use rand::random;
    use uuid::Uuid;

    #[tokio::test]
    async fn gc_task() {
        install_test_trace_subscriber();

        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let ds = Arc::new(ds);
        let vdaf = dummy_vdaf::Vdaf::new();

        // Setup.
        let task = ds
            .run_tx(|tx| {
                let clock = clock.clone();
                Box::pin(async move {
                    const REPORT_EXPIRY_AGE: Duration = Duration::from_seconds(3600);
                    let task = TaskBuilder::new(
                        task::QueryType::TimeInterval,
                        VdafInstance::Fake,
                        Role::Leader,
                    )
                    .with_report_expiry_age(Some(REPORT_EXPIRY_AGE))
                    .build();
                    tx.put_task(&task).await?;

                    let client_timestamp = clock
                        .now()
                        .sub(&REPORT_EXPIRY_AGE)
                        .unwrap()
                        .sub(&Duration::from_seconds(1))
                        .unwrap();
                    let report = LeaderStoredReport::new_dummy(*task.id(), client_timestamp);
                    tx.put_client_report(&report).await.unwrap();

                    let batch_identifier =
                        Interval::new(client_timestamp, Duration::from_seconds(1)).unwrap();
                    let aggregation_job = AggregationJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        random(),
                        Some(batch_identifier),
                        AggregationParam(0),
                        AggregationJobState::InProgress,
                    );
                    tx.put_aggregation_job(&aggregation_job).await.unwrap();

                    let report_aggregation = ReportAggregation::<0, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        *aggregation_job.id(),
                        *report.metadata().id(),
                        client_timestamp,
                        0,
                        ReportAggregationState::Start,
                    );
                    tx.put_report_aggregation(&report_aggregation)
                        .await
                        .unwrap();

                    let collect_job = CollectJob::<0, TimeInterval, dummy_vdaf::Vdaf>::new(
                        *task.id(),
                        Uuid::new_v4(),
                        batch_identifier,
                        AggregationParam(0),
                        CollectJobState::Start,
                    );
                    tx.put_collect_job(&collect_job).await.unwrap();

                    Ok(task)
                })
            })
            .await
            .unwrap();

        // Run.
        let task = Arc::new(task);
        GarbageCollector::new(Arc::clone(&ds), clock.clone())
            .gc_task(Arc::clone(&task))
            .await
            .unwrap();

        // Verify.
        let (client_reports, aggregation_jobs, report_aggregations, collect_jobs) = ds
            .run_tx(|tx| {
                let (clock, vdaf, task) = (clock.clone(), vdaf.clone(), Arc::clone(&task));
                Box::pin(async move {
                    let client_reports = tx
                        .get_client_reports_for_task::<0, dummy_vdaf::Vdaf>(&vdaf, task.id())
                        .await?;
                    let aggregation_jobs = tx
                        .get_aggregation_jobs_for_task::<0, TimeInterval, dummy_vdaf::Vdaf>(
                            task.id(),
                        )
                        .await?;
                    let report_aggregations = tx
                        .get_report_aggregations_for_task::<0, dummy_vdaf::Vdaf>(
                            &vdaf,
                            &Role::Leader,
                            task.id(),
                        )
                        .await?;
                    let collect_jobs = tx
                        .get_collect_jobs_intersecting_interval::<0, dummy_vdaf::Vdaf>(
                            task.id(),
                            &Interval::new(
                                Time::from_seconds_since_epoch(0),
                                Duration::from_seconds(clock.now().as_seconds_since_epoch()),
                            )
                            .unwrap(),
                        )
                        .await?;

                    Ok((
                        client_reports,
                        aggregation_jobs,
                        report_aggregations,
                        collect_jobs,
                    ))
                })
            })
            .await
            .unwrap();
        assert!(client_reports.is_empty());
        assert!(aggregation_jobs.is_empty());
        assert!(report_aggregations.is_empty());
        assert!(collect_jobs.is_empty());
    }
}
