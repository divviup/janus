use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration as StdDuration,
};

use futures::future::BoxFuture;
use janus_aggregator::{
    aggregator::{
        self, aggregation_job_creator::AggregationJobCreator,
        aggregation_job_driver::AggregationJobDriver, collection_job_driver::CollectionJobDriver,
        garbage_collector::GarbageCollector, http_handlers::aggregator_handler,
        Config as AggregatorConfig,
    },
    cache::GlobalHpkeKeypairCache,
};
use janus_aggregator_core::{
    datastore::{
        self,
        models::{AcquiredAggregationJob, AcquiredCollectionJob, Lease},
        test_util::{ephemeral_datastore, EphemeralDatastore},
        Datastore,
    },
    task::{
        test_util::{Task, TaskBuilder},
        QueryType,
    },
};
use janus_client::{default_http_client, Client};
use janus_collector::Collector;
use janus_core::{test_util::runtime::TestRuntime, time::MockClock, Runtime};
use prio::vdaf::prio3::Prio3Histogram;
use tokio::net::TcpListener;

use crate::simulation::{
    model::Input,
    proxy::{FaultInjector, FaultInjectorHandler, InspectHandler, InspectMonitor},
    run::State,
};

// Labels for TestRuntimeManager.
static LEADER_AGGREGATOR_SERVER: &str = "leader_aggregator_server";
static HELPER_AGGREGATOR_SERVER: &str = "helper_aggregator_server";

const BATCH_AGGREGATION_SHARD_COUNT: usize = 32;

pub(super) struct SimulationAggregator {
    pub(super) _ephemeral_datastore: EphemeralDatastore,
    pub(super) datastore: Arc<Datastore<MockClock>>,
    pub(super) socket_address: SocketAddr,
    pub(super) fault_injector: FaultInjector,
    pub(super) inspect_monitor: InspectMonitor,
}

impl SimulationAggregator {
    pub(super) async fn new(server_runtime: TestRuntime, state: &State) -> Self {
        let ephemeral_datastore = ephemeral_datastore().await;
        let datastore = Arc::new(ephemeral_datastore.datastore(state.clock.clone()).await);

        let aggregator_config = AggregatorConfig {
            // Set this to 1 because report uploads will be serialized.
            max_upload_batch_size: 1,
            max_upload_batch_write_delay: StdDuration::from_secs(0),
            batch_aggregation_shard_count: 32,
            global_hpke_configs_refresh_interval: GlobalHpkeKeypairCache::DEFAULT_REFRESH_INTERVAL,
            // We only support Taskprov on the helper side, so leave it disabled.
            taskprov_config: Default::default(),
        };

        let aggregator_handler = aggregator_handler(
            Arc::clone(&datastore),
            state.clock.clone(),
            &state.meter,
            aggregator_config,
        )
        .await
        .unwrap();

        let inspect_handler = InspectHandler::new(aggregator_handler);
        let inspect_monitor = inspect_handler.monitor();

        let fault_injector_handler = FaultInjectorHandler::new(inspect_handler);
        let fault_injector = fault_injector_handler.controller();

        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket_address = server.local_addr().unwrap();
        let aggregator_future = trillium_tokio::config()
            .with_stopper(state.stopper.clone())
            .without_signals()
            .with_prebound_server(server)
            .run_async(fault_injector_handler);
        server_runtime.spawn(aggregator_future);

        SimulationAggregator {
            _ephemeral_datastore: ephemeral_datastore,
            datastore,
            socket_address,
            fault_injector,
            inspect_monitor,
        }
    }
}

type JobAcquirerCallback<Job> =
    Box<dyn Fn(usize) -> BoxFuture<'static, Result<Vec<Lease<Job>>, datastore::Error>>>;
type JobStepperCallback<Job, E> = Box<dyn Fn(Lease<Job>) -> BoxFuture<'static, Result<(), E>>>;

pub(super) struct Components {
    pub(super) leader: SimulationAggregator,
    pub(super) helper: SimulationAggregator,
    pub(super) http_client: reqwest::Client,
    pub(super) client: Client<Prio3Histogram>,
    pub(super) leader_garbage_collector: GarbageCollector<MockClock>,
    pub(super) helper_garbage_collector: GarbageCollector<MockClock>,
    pub(super) aggregation_job_creator: Arc<AggregationJobCreator<MockClock>>,
    pub(super) aggregation_job_driver_acquirer_cb: JobAcquirerCallback<AcquiredAggregationJob>,
    pub(super) aggregation_job_driver_stepper_cb:
        JobStepperCallback<AcquiredAggregationJob, anyhow::Error>,
    pub(super) collection_job_driver_acquirer_cb: JobAcquirerCallback<AcquiredCollectionJob>,
    pub(super) collection_job_driver_stepper_cb:
        JobStepperCallback<AcquiredCollectionJob, aggregator::Error>,
    pub(super) collector: Collector<Prio3Histogram>,
}

impl Components {
    pub(super) async fn setup(input: &Input, state: &mut State) -> (Self, Task) {
        let leader = SimulationAggregator::new(
            state.runtime_manager.with_label(LEADER_AGGREGATOR_SERVER),
            state,
        )
        .await;

        let helper = SimulationAggregator::new(
            state.runtime_manager.with_label(HELPER_AGGREGATOR_SERVER),
            state,
        )
        .await;

        let query_type = if input.is_fixed_size {
            QueryType::FixedSize {
                max_batch_size: input.config.max_batch_size,
                batch_time_window_size: input.config.batch_time_window_size,
            }
        } else {
            QueryType::TimeInterval
        };
        let task = TaskBuilder::new(query_type, state.vdaf_instance.clone())
            .with_leader_aggregator_endpoint(
                format!("http://{}/", leader.socket_address)
                    .parse()
                    .unwrap(),
            )
            .with_helper_aggregator_endpoint(
                format!("http://{}/", helper.socket_address)
                    .parse()
                    .unwrap(),
            )
            .with_time_precision(input.config.time_precision)
            .with_min_batch_size(input.config.min_batch_size)
            .with_report_expiry_age(input.config.report_expiry_age)
            .build();
        let leader_task = task.leader_view().unwrap();
        let helper_task = task.helper_view().unwrap();
        leader
            .datastore
            .put_aggregator_task(&leader_task)
            .await
            .unwrap();
        helper
            .datastore
            .put_aggregator_task(&helper_task)
            .await
            .unwrap();

        let http_client = default_http_client().unwrap();
        let client = Client::builder(
            *task.id(),
            task.leader_aggregator_endpoint().clone(),
            task.helper_aggregator_endpoint().clone(),
            *task.time_precision(),
            state.vdaf.clone(),
        )
        .with_http_client(http_client.clone())
        .build()
        .await
        .unwrap();

        let leader_garbage_collector = GarbageCollector::new(
            Arc::clone(&leader.datastore),
            &state.meter,
            100,
            100,
            100,
            1,
            None,
        );

        let helper_garbage_collector = GarbageCollector::new(
            Arc::clone(&helper.datastore),
            &state.meter,
            100,
            100,
            100,
            1,
            None,
        );

        let aggregation_job_creator = Arc::new(AggregationJobCreator::new(
            Arc::clone(&leader.datastore),
            state.meter.clone(),
            StdDuration::from_secs(0), // unused
            StdDuration::from_secs(0), // unused
            input.config.min_aggregation_job_size,
            input.config.max_aggregation_job_size,
        ));

        let aggregation_job_driver = Arc::new(AggregationJobDriver::new(
            reqwest::Client::new(),
            &state.meter,
            BATCH_AGGREGATION_SHARD_COUNT.try_into().unwrap(),
        ));
        let aggregation_job_driver_acquirer_cb = Box::new(
            aggregation_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&leader.datastore),
                StdDuration::from_secs(600),
            ),
        );
        let aggregation_job_driver_stepper_cb = Box::new(
            aggregation_job_driver.make_job_stepper_callback(Arc::clone(&leader.datastore), 1),
        );

        let collection_job_driver = Arc::new(CollectionJobDriver::new(
            reqwest::Client::new(),
            &state.meter,
            BATCH_AGGREGATION_SHARD_COUNT.try_into().unwrap(),
        ));
        let collection_job_driver_acquirer_cb =
            Box::new(collection_job_driver.make_incomplete_job_acquirer_callback(
                Arc::clone(&leader.datastore),
                StdDuration::from_secs(600),
            ));
        let collection_job_driver_stepper_cb = Box::new(
            collection_job_driver.make_job_stepper_callback(Arc::clone(&leader.datastore), 1),
        );

        let collector = Collector::builder(
            *task.id(),
            task.leader_aggregator_endpoint().clone(),
            task.collector_auth_token().clone(),
            task.collector_hpke_keypair().clone(),
            state.vdaf.clone(),
        )
        .build()
        .unwrap();

        (
            Self {
                leader,
                helper,
                http_client,
                client,
                leader_garbage_collector,
                helper_garbage_collector,
                aggregation_job_creator,
                aggregation_job_driver_acquirer_cb,
                aggregation_job_driver_stepper_cb,
                collection_job_driver_acquirer_cb,
                collection_job_driver_stepper_cb,
                collector,
            },
            task,
        )
    }
}
