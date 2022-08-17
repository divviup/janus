//! Functionality for tests interacting with Janus (<https://github.com/divviup/janus>).

use futures::FutureExt;
use janus_core::{
    message::Duration,
    test_util::kubernetes::{Cluster, PortForward},
    time::RealClock,
    TokioRuntime,
};
use janus_server::{
    aggregator::{
        aggregate_share::CollectJobDriver, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, aggregator_filter,
    },
    binary_utils::{database_pool, datastore, job_driver::JobDriver},
    config::DbConfig,
    datastore::test_util::{ephemeral_datastore, DbHandle},
    task::Task,
};
use k8s_openapi::api::core::v1::Secret;
use opentelemetry::global::meter;
use portpicker::pick_unused_port;
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{mpsc, Arc},
    time,
};
use tokio::{select, sync::oneshot, task, try_join};
use tracing::debug;
use url::Url;
use warp::Filter;

/// Represents a running Janus test instance
#[allow(clippy::large_enum_variant)]
pub enum Janus {
    /// Janus components are spawned in-process, and completely destroyed once the test ends.
    InProcess {
        // Dependencies.
        _db_handle: DbHandle,

        // Task lifetime management.
        start_shutdown_sender: Option<oneshot::Sender<()>>,
        shutdown_complete_receiver: Option<mpsc::Receiver<()>>,
    },
    /// Janus components are assumed to already be running in the Kubernetes cluster. Running tests
    /// against the cluster will persistently mutate the Janus deployment, for instance by writing
    /// new tasks and reports into its datastore.
    KubernetesCluster { port_forwards: Vec<PortForward> },
}

impl Janus {
    // Create & start a new hermetic Janus test instance listening on the given port, configured
    // to service the given task.
    pub async fn new_in_process(port: u16, task: &Task) -> Self {
        // Start datastore.
        let (datastore, db_handle) = ephemeral_datastore(RealClock::default()).await;
        let datastore = Arc::new(datastore);

        // Make sure to do this *before* starting the Janus components so that the task will be
        // present on startup.
        datastore.put_task(task).await.unwrap();

        // Start aggregator server.
        let (server_shutdown_sender, server_shutdown_receiver) = oneshot::channel();
        let aggregator_filter = task
            .aggregator_url(task.role)
            .unwrap()
            .path_segments()
            .unwrap()
            .filter_map(|s| (!s.is_empty()).then(|| warp::path(s.to_owned()).boxed()))
            .reduce(|x, y| x.and(y).boxed())
            .unwrap_or_else(|| warp::any().boxed())
            .and(aggregator_filter(datastore, RealClock::default()).unwrap());
        let server = warp::serve(aggregator_filter);
        let server_task_handle = task::spawn(async move {
            server
                .bind_with_graceful_shutdown(
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                    server_shutdown_receiver.map(Result::unwrap),
                )
                .1
                .await
        });

        // Start aggregation job creator.
        let (
            aggregation_job_creator_shutdown_sender,
            mut aggregation_job_creator_shutdown_receiver,
        ) = oneshot::channel();
        let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
            db_handle.datastore(RealClock::default()),
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
        let datastore = Arc::new(db_handle.datastore(RealClock::default()));
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
        let datastore = Arc::new(db_handle.datastore(RealClock::default()));
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

        Self::InProcess {
            _db_handle: db_handle,
            start_shutdown_sender: Some(start_shutdown_sender),
            shutdown_complete_receiver: Some(shutdown_complete_receiver),
        }
    }

    /// Set up a test case running in a Kubernetes cluster where Janus components and a datastore
    /// are assumed to already be deployed.
    pub async fn new_with_kubernetes_cluster<P>(
        kubeconfig_path: P,
        kubernetes_context_name: &str,
        namespace: &str,
        task: &Task,
        aggregator_local_port: u16,
    ) -> Self
    where
        P: AsRef<Path>,
    {
        let cluster = Cluster::new(kubeconfig_path, kubernetes_context_name);

        // Read the Postgres password and the datastore encryption key from Kubernetes secrets
        let secrets_api: kube::Api<Secret> =
            kube::Api::namespaced(cluster.client().await, namespace);

        let database_password_secret = secrets_api.get("postgresql").await.unwrap();
        let database_password = String::from_utf8(
            database_password_secret
                .data
                .unwrap()
                .get("postgres-password")
                .unwrap()
                .0
                .clone(),
        )
        .unwrap();

        let datastore_key_secret = secrets_api.get("datastore-key").await.unwrap();
        let datastore_key = String::from_utf8(
            datastore_key_secret
                .data
                .unwrap()
                .get("datastore_key")
                .unwrap()
                .0
                .clone(),
        )
        .unwrap();

        // Forward database port so we can provision the task. We assume here that there is a
        // service named "postgresql" listening on port 5432. We could instead look up the service
        // by some label and dynamically discover its port, but being coupled to a label value isn't
        // much different than being coupled to a service name.
        let local_db_port = pick_unused_port().unwrap();
        let _datastore_port_forward = cluster
            .forward_port(namespace, "postgresql", local_db_port, 5432)
            .await;
        debug!("forwarded DB port");

        let pool = database_pool(
            &DbConfig {
                url: Url::parse(&format!(
                    "postgres://postgres:{database_password}@127.0.0.1:{local_db_port}/postgres"
                ))
                .unwrap(),
                connection_pool_timeouts_secs: 60,
            },
            None,
        )
        .await
        .unwrap();

        // Since the Janus components are already running when the task is provisioned, they all
        // must be configured to frequently poll the datastore for new tasks, or the test that
        // depends on this task being defined will likely time out or otherwise fail.
        // This should become more robust in the future when we implement dynamic task provisioning
        // (#44).
        datastore(pool, RealClock::default(), &[datastore_key])
            .unwrap()
            .put_task(task)
            .await
            .unwrap();

        let aggregator_port_forward = cluster
            .forward_port(namespace, "aggregator", aggregator_local_port, 80)
            .await;

        Self::KubernetesCluster {
            port_forwards: vec![aggregator_port_forward],
        }
    }
}

impl Drop for Janus {
    fn drop(&mut self) {
        if let Self::InProcess {
            start_shutdown_sender,
            shutdown_complete_receiver,
            ..
        } = self
        {
            start_shutdown_sender.take().unwrap().send(()).unwrap();
            shutdown_complete_receiver.take().unwrap().recv().unwrap();
        }
    }
}
