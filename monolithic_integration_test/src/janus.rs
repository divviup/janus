//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

use http::HeaderMap;
use janus_core::{message::Duration, time::RealClock, TokioRuntime};
use janus_server::{
    aggregator::{
        aggregate_share::CollectJobDriver, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, aggregator_server,
    },
    binary_utils::job_driver::JobDriver,
    datastore::test_util::{ephemeral_datastore, DbHandle},
    task::Task,
};
use opentelemetry::global::meter;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{mpsc, Arc},
    time,
};
use tokio::{select, sync::oneshot, task, try_join};

/// Represents a running Janus test instance.
pub struct Janus {
    // Dependencies.
    _db_handle: DbHandle,

    // Task lifetime management.
    start_shutdown_sender: Option<oneshot::Sender<()>>,
    shutdown_complete_receiver: Option<mpsc::Receiver<()>>,
}

impl Janus {
    // Create & start a new hermetic Janus test instance listening on the given port, configured
    // to service the given task.
    pub async fn new(port: u16, task: &Task) -> Self {
        // Start datastore.
        let (datastore, _db_handle) = ephemeral_datastore(RealClock::default()).await;
        let datastore = Arc::new(datastore);

        // Write task into datastore.
        datastore
            .run_tx(|tx| {
                let task = task.clone();
                Box::pin(async move { tx.put_task(&task).await })
            })
            .await
            .unwrap();

        // Start aggregator server.
        let (server_shutdown_sender, server_shutdown_receiver) = oneshot::channel();
        let (_, leader_server) = aggregator_server(
            Arc::clone(&datastore),
            RealClock::default(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            HeaderMap::new(),
            async move { server_shutdown_receiver.await.unwrap() },
        )
        .unwrap();
        let server_task_handle = task::spawn(leader_server);

        // Start aggregation job creator.
        let (
            aggregation_job_creator_shutdown_sender,
            mut aggregation_job_creator_shutdown_receiver,
        ) = oneshot::channel();
        let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
            _db_handle.datastore(RealClock::default()),
            RealClock::default(),
            time::Duration::from_secs(60),
            time::Duration::from_secs(1),
            1,
            100,
        ));
        let aggregation_job_creator_handle = task::spawn(async move {
            select! {
                _ = aggregation_job_creator.run() => unreachable!(),
                _ = &mut aggregation_job_creator_shutdown_receiver => (),
            }
        });

        // Start aggregation job driver.
        let (aggregation_job_driver_shutdown_sender, mut aggregation_job_driver_shutdown_receiver) =
            oneshot::channel();
        let datastore = Arc::new(_db_handle.datastore(RealClock::default()));
        let aggregation_job_driver_meter = meter("aggregation_job_driver");
        let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &aggregation_job_driver_meter,
        ));
        let aggregation_job_driver = Arc::new(JobDriver::new(
            RealClock::default(),
            TokioRuntime,
            aggregation_job_driver_meter,
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::ZERO,
            aggregation_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&datastore),
                Duration::from_seconds(10),
            ),
            aggregation_job_driver.make_job_stepper_callback(Arc::clone(&datastore), 3),
        ));
        let aggregation_job_driver_handle = task::spawn(async move {
            select! {
                _ = aggregation_job_driver.run() => unreachable!(),
                _ = &mut aggregation_job_driver_shutdown_receiver => (),
            }
        });

        // Start collect job driver.
        let (collect_job_driver_shutdown_sender, mut collect_job_driver_shutdown_receiver) =
            oneshot::channel();
        let datastore = Arc::new(_db_handle.datastore(RealClock::default()));
        let collect_job_driver_meter = meter("collect_job_driver");
        let collect_job_driver = Arc::new(CollectJobDriver::new(
            reqwest::Client::builder().build().unwrap(),
            &collect_job_driver_meter,
        ));
        let collect_job_driver = Arc::new(JobDriver::new(
            RealClock::default(),
            TokioRuntime,
            collect_job_driver_meter,
            Duration::from_seconds(1),
            Duration::from_seconds(1),
            10,
            Duration::ZERO,
            collect_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&datastore),
                Duration::from_seconds(10),
            ),
            collect_job_driver.make_job_stepper_callback(Arc::clone(&datastore), 3),
        ));
        let collect_job_driver_handle = task::spawn(async move {
            select! {
                _ = collect_job_driver.run() => unreachable!(),
                _ = &mut collect_job_driver_shutdown_receiver => (),
            }
        });

        // Start the "shutdown" task, allowing us to do asynchronous shutdown work in the
        // synchronous drop implementation. (We use an async oneshot channel for "start shutdown"
        // and a sync mpsc channel for "shutdown complete" to allow us to do the required operations
        // from a sync context.)
        let (start_shutdown_sender, start_shutdown_receiver) = oneshot::channel();
        let (shutdown_complete_sender, shutdown_complete_receiver) = mpsc::channel();
        task::spawn(async move {
            start_shutdown_receiver.await.unwrap();

            server_shutdown_sender.send(()).unwrap();
            aggregation_job_creator_shutdown_sender.send(()).unwrap();
            aggregation_job_driver_shutdown_sender.send(()).unwrap();
            collect_job_driver_shutdown_sender.send(()).unwrap();

            try_join!(
                server_task_handle,
                aggregation_job_creator_handle,
                aggregation_job_driver_handle,
                collect_job_driver_handle
            )
            .unwrap();

            shutdown_complete_sender.send(()).unwrap();
        });

        Janus {
            _db_handle,
            start_shutdown_sender: Some(start_shutdown_sender),
            shutdown_complete_receiver: Some(shutdown_complete_receiver),
        }
    }
}

impl Drop for Janus {
    fn drop(&mut self) {
        let start_shutdown_sender = self.start_shutdown_sender.take().unwrap();
        let shutdown_complete_receiver = self.shutdown_complete_receiver.take().unwrap();

        start_shutdown_sender.send(()).unwrap();
        shutdown_complete_receiver.recv().unwrap();
    }
}
