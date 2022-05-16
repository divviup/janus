use anyhow::{anyhow, Context, Result};
use futures::{
    future::{try_join_all, FutureExt},
    try_join,
};
use janus::{
    hpke::{self, associated_data_for_report_share, HpkeApplicationInfo, Label},
    message::{Duration, Report, Role, TaskId, Time},
    time::{Clock, RealClock},
};
use janus_server::{
    binary_utils::datastore,
    config::AggregationJobDriverConfig,
    datastore::{
        self,
        models::{AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState},
        Datastore,
    },
    message::{
        AggregateReq, AggregateReqBody, AggregateResp, AggregationJobId, AuthenticatedEncoder,
        AuthenticatedResponseDecoder, ReportShare, Transition, TransitionError,
        TransitionTypeSpecificData,
    },
    task::{Task, VdafInstance},
    trace::install_trace_subscriber,
};
use prio::{
    codec::{Encode, ParameterizedDecode},
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128Histogram, Prio3Aes128Sum},
        PrepareTransition,
    },
};
use std::{
    fmt::{self, Debug, Formatter},
    fs,
    path::PathBuf,
    sync::Arc,
};
use structopt::StructOpt;
use tokio::{
    sync::Semaphore,
    task,
    time::{self},
};
use tracing::{debug, error, info};

#[derive(StructOpt)]
#[structopt(
    name = "janus-aggregation-job-driver",
    about = "Janus aggregation job driver",
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

const CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/aggregation_job_driver",
);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Read arguments, read & parse config.
    let options = Options::from_args();
    let config: AggregationJobDriverConfig = {
        let config_content = fs::read_to_string(&options.config_file)
            .with_context(|| format!("couldn't read config file {:?}", options.config_file))?;
        serde_yaml::from_str(&config_content)
            .with_context(|| format!("couldn't parse config file {:?}", options.config_file))?
    };
    install_trace_subscriber(&config.logging_config)
        .context("couldn't install tracing subscriber")?;

    info!(?options, ?config, "Starting aggregation job driver");

    // Connect to database & create other dependencies for AggregationJobDriver.
    let clock = RealClock::default();
    let datastore = datastore(
        clock,
        config.database,
        options.database_password,
        options.datastore_keys,
    )
    .context("couldn't connect to database")?;

    let http_client = reqwest::Client::builder()
        .user_agent(CLIENT_USER_AGENT)
        .build()
        .context("couldn't create HTTP client")?;

    // Start running.
    Arc::new(AggregationJobDriver {
        datastore,
        clock,
        http_client,
        min_aggregation_job_discovery_delay: Duration::from_seconds(
            config.min_aggregation_job_discovery_delay_secs,
        ),
        max_aggregation_job_discovery_delay: Duration::from_seconds(
            config.max_aggregation_job_discovery_delay_secs,
        ),
        max_concurrent_aggregation_job_workers: config.max_concurrent_aggregation_job_workers,
        aggregation_worker_lease_duration: Duration::from_seconds(
            config.aggregation_worker_lease_duration_secs,
        ),
        aggregation_worker_lease_clock_skew_allowance: Duration::from_seconds(
            config.aggregation_worker_lease_clock_skew_allowance_secs,
        ),
    })
    .run()
    .await
}

struct AggregationJobDriver<C: Clock> {
    // Dependencies.
    datastore: Datastore<C>,
    clock: C,
    http_client: reqwest::Client,

    // Configuration.
    min_aggregation_job_discovery_delay: Duration,
    max_aggregation_job_discovery_delay: Duration,
    max_concurrent_aggregation_job_workers: usize,
    aggregation_worker_lease_duration: Duration,
    aggregation_worker_lease_clock_skew_allowance: Duration,
}

impl<C: Clock> AggregationJobDriver<C> {
    #[tracing::instrument(skip(self))]
    async fn run(self: Arc<Self>) -> ! {
        let sem = Arc::new(Semaphore::new(self.max_concurrent_aggregation_job_workers));
        let mut job_discovery_delay = Duration::ZERO;

        loop {
            // Wait out our job discovery delay, if any.
            time::sleep(time::Duration::from_secs(job_discovery_delay.as_seconds())).await;

            // Wait until we are able to start at least one worker. (permit will be immediately released)
            //
            // Unwrap safety: Semaphore::acquire is documented as only returning an error if the
            // semaphore is closed, and we never close this semaphore.
            let _ = sem.acquire().await.unwrap();

            // Acquire some aggregation jobs which are ready to be stepped.
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
            info!(max_acquire_count, "Acquiring aggregation jobs");
            let acquired_jobs = self
                .datastore
                .run_tx(|tx| {
                    let lease_duration = self.aggregation_worker_lease_duration;
                    Box::pin(async move {
                        tx.acquire_incomplete_aggregation_jobs(lease_duration, max_acquire_count)
                            .await
                    })
                })
                .await;
            let acquired_jobs = match acquired_jobs {
                Ok(acquired_jobs) => acquired_jobs,
                Err(err) => {
                    error!(?err, "Couldn't acquire aggregation jobs");
                    // Go ahead and step job discovery delay in this error case to ensure we don't
                    // tightly loop running transactions that will fail without any delay.
                    job_discovery_delay = self.step_job_discovery_delay(job_discovery_delay);
                    continue;
                }
            };
            if acquired_jobs.is_empty() {
                debug!("No aggregation jobs available");
                job_discovery_delay = self.step_job_discovery_delay(job_discovery_delay);
                continue;
            }
            info!(
                acquired_job_count = acquired_jobs.len(),
                "Acquired aggregation jobs"
            );

            // Start up tasks for each acquired aggregation job.
            job_discovery_delay = Duration::ZERO;
            for (task_id, vdaf, aggregation_job_id, lease_expiry) in acquired_jobs {
                info!(
                    ?task_id,
                    ?aggregation_job_id,
                    ?lease_expiry,
                    "Stepping aggregation job"
                );
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
                    async move {
                        match time::timeout(
                            this.effective_lease_duration(lease_expiry),
                            this.step_aggregation_job(vdaf, task_id, aggregation_job_id),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                debug!(?task_id, ?aggregation_job_id, "Aggregation job stepped")
                            }

                            Ok(Err(err)) => {
                                error!(
                                    ?task_id,
                                    ?aggregation_job_id,
                                    ?err,
                                    "Couldn't step aggregation job"
                                )
                            }

                            Err(err) => error!(
                                ?task_id,
                                ?aggregation_job_id,
                                ?err,
                                "Couldn't step aggregation job"
                            ),
                        }
                        drop(permit);
                    }
                });
            }
        }
    }

    async fn step_aggregation_job(
        &self,
        vdaf: VdafInstance,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
    ) -> Result<()> {
        match vdaf {
            VdafInstance::Prio3Aes128Count => {
                let vdaf = Prio3Aes128Count::new(2)?;
                self.step_aggregation_job_generic(vdaf, task_id, aggregation_job_id)
                    .await
            }

            VdafInstance::Prio3Aes128Sum { bits } => {
                let vdaf = Prio3Aes128Sum::new(2, bits)?;
                self.step_aggregation_job_generic(vdaf, task_id, aggregation_job_id)
                    .await
            }

            VdafInstance::Prio3Aes128Histogram { buckets } => {
                let vdaf = Prio3Aes128Histogram::new(2, &buckets)?;
                self.step_aggregation_job_generic(vdaf, task_id, aggregation_job_id)
                    .await
            }

            _ => panic!("VDAF {:?} is not yet supported", vdaf),
        }
    }

    async fn step_aggregation_job_generic<A: vdaf::Aggregator>(
        &self,
        vdaf: A,
        task_id: TaskId,
        aggregation_job_id: AggregationJobId,
    ) -> Result<()>
    where
        A: 'static + Send + Sync,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: PartialEq + Eq + Send + Sync + for<'a> TryFrom<&'a [u8]>,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareStep: PartialEq + Eq + Send + Sync + Encode + ParameterizedDecode<A::VerifyParam>,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
        A::VerifyParam: Send + Sync + ParameterizedDecode<A>,
    {
        // Read all information about the aggregation job.
        let vdaf = Arc::new(vdaf);
        let (task, aggregation_job, report_aggregations, client_reports, verify_param) = self
            .datastore
            .run_tx(|tx| {
                let vdaf = Arc::clone(&vdaf);
                Box::pin(async move {
                    let task = tx.get_task(task_id).await?.ok_or_else(|| {
                        datastore::Error::User(anyhow!("couldn't find task {}", task_id).into())
                    })?;
                    let verify_param =
                        A::VerifyParam::get_decoded_with_param(&vdaf, &task.vdaf_verify_parameter)?;

                    let aggregation_job_future =
                        tx.get_aggregation_job::<A>(task_id, aggregation_job_id);
                    let report_aggregations_future = tx
                        .get_report_aggregations_for_aggregation_job::<A>(
                            &verify_param,
                            task_id,
                            aggregation_job_id,
                        );

                    let (aggregation_job, report_aggregations) =
                        try_join!(aggregation_job_future, report_aggregations_future)?;
                    let aggregation_job = aggregation_job.ok_or_else(|| {
                        datastore::Error::User(
                            anyhow!(
                                "couldn't find aggregation job {} for task {}",
                                aggregation_job_id,
                                task_id
                            )
                            .into(),
                        )
                    })?;

                    // Read client reports, but only for report aggregations in state START.
                    // TODO(brandon): create "get_client_reports_for_aggregation_job" datastore
                    // operation to avoid needing to join many futures?
                    let client_reports =
                        try_join_all(report_aggregations.iter().filter_map(|report_aggregation| {
                            if report_aggregation.state == ReportAggregationState::Start {
                                Some(tx.get_client_report(task_id, report_aggregation.nonce).map(
                                    |rslt| {
                                        rslt.context(format!(
                                            "couldn't get report {} for task {}",
                                            report_aggregation.nonce, task_id,
                                        ))
                                        .and_then(
                                            |maybe_report| {
                                                maybe_report.ok_or_else(|| {
                                                    anyhow!(
                                                        "couldn't find report {} for task {}",
                                                        report_aggregation.nonce,
                                                        task_id
                                                    )
                                                })
                                            },
                                        )
                                    },
                                ))
                            } else {
                                None
                            }
                        }))
                        .await
                        .map_err(|err| datastore::Error::User(err.into()))?;

                    Ok((
                        task,
                        aggregation_job,
                        report_aggregations,
                        client_reports,
                        verify_param,
                    ))
                })
            })
            .await?;

        // Figure out the next step based on the non-error report aggregation states, and dispatch accordingly.
        let (mut saw_start, mut saw_waiting, mut saw_finished) = (false, false, false);
        for report_aggregation in &report_aggregations {
            match report_aggregation.state {
                ReportAggregationState::Start => saw_start = true,
                ReportAggregationState::Waiting(_, _) => saw_waiting = true,
                ReportAggregationState::Finished(_) => saw_finished = true,
                ReportAggregationState::Failed(_) | ReportAggregationState::Invalid => (), // ignore failure aggregation states
            }
        }
        match (saw_start, saw_waiting, saw_finished) {
            // Only saw report aggregations in state "start" (or failed or invalid).
            (true, false, false) => self.step_aggregation_job_aggregate_init(
                vdaf.as_ref(), task, aggregation_job, report_aggregations, client_reports, verify_param).await,

            // Only saw report aggregations in state "waiting" (or failed or invalid).
            (false, true, false) => self.step_aggregation_job_aggregate_continue(
                vdaf.as_ref(), task, aggregation_job, report_aggregations).await,

            _ => return Err(anyhow!("unexpected combination of report aggregation states (saw_start = {}, saw_waiting = {}, saw_finished = {})", saw_start, saw_waiting, saw_finished)),
        }
    }

    async fn step_aggregation_job_aggregate_init<A: vdaf::Aggregator>(
        &self,
        vdaf: &A,
        task: Task,
        aggregation_job: AggregationJob<A>,
        report_aggregations: Vec<ReportAggregation<A>>,
        client_reports: Vec<Report>,
        verify_param: A::VerifyParam,
    ) -> Result<()>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: PartialEq + Eq + Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareStep: PartialEq + Eq + Send + Sync + Encode,
        A::PrepareMessage: PartialEq + Eq + Send + Sync,
    {
        // Zip the report aggregations at start with the client reports, verifying that their nonces
        // match. We use asserts here as the conditions we are checking should be guaranteed by the
        // caller.
        let report_aggregations: Vec<_> = report_aggregations
            .into_iter()
            .filter(|report_aggregation| report_aggregation.state == ReportAggregationState::Start)
            .collect();
        assert_eq!(report_aggregations.len(), client_reports.len());
        let reports: Vec<_> = report_aggregations
            .into_iter()
            .zip(client_reports.into_iter())
            .collect();
        for (report_aggregation, client_report) in &reports {
            assert_eq!(report_aggregation.task_id, client_report.task_id());
            assert_eq!(report_aggregation.nonce, client_report.nonce());
        }

        // Compute report shares to send to helper, and decrypt our input shares & initialize
        // preparation state.
        let mut report_aggregations_to_write = Vec::new();
        let mut report_shares = Vec::new();
        let mut stepped_aggregations = Vec::new();
        for (mut report_aggregation, report) in reports {
            // Retrieve input shares.
            let leader_encrypted_input_share = match report
                .encrypted_input_shares()
                .get(Role::Leader.index().unwrap())
            {
                Some(leader_encrypted_input_share) => leader_encrypted_input_share,
                None => {
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, "Client report missing leader encrypted input share");
                    report_aggregation.state = ReportAggregationState::Invalid;
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };

            let helper_encrypted_input_share = match report
                .encrypted_input_shares()
                .get(Role::Helper.index().unwrap())
            {
                Some(helper_encrypted_input_share) => helper_encrypted_input_share,
                None => {
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, "Client report missing helper encrypted input share");
                    report_aggregation.state = ReportAggregationState::Invalid;
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };

            // Decrypt leader input share & transform into our first transition.
            let (hpke_config, hpke_private_key) = match task
                .hpke_keys
                .get(&leader_encrypted_input_share.config_id())
            {
                Some((hpke_config, hpke_private_key)) => (hpke_config, hpke_private_key),
                None => {
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, hpke_config_id = %leader_encrypted_input_share.config_id(), "Leader encrypted input share references unknown HPKE config ID");
                    report_aggregation.state =
                        ReportAggregationState::Failed(TransitionError::HpkeUnknownConfigId);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };
            let hpke_application_info =
                HpkeApplicationInfo::new(task.id, Label::InputShare, Role::Client, Role::Leader);
            let associated_data =
                associated_data_for_report_share(report.nonce(), report.extensions());
            let leader_input_share_bytes = match hpke::open(
                hpke_config,
                hpke_private_key,
                &hpke_application_info,
                leader_encrypted_input_share,
                &associated_data,
            ) {
                Ok(leader_input_share_bytes) => leader_input_share_bytes,
                Err(err) => {
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, ?err, "Couldn't decrypt leader's encrypted input share");
                    report_aggregation.state =
                        ReportAggregationState::Failed(TransitionError::HpkeDecryptError);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };
            let leader_input_share = match A::InputShare::get_decoded_with_param(
                &verify_param,
                &leader_input_share_bytes,
            ) {
                Ok(leader_input_share) => leader_input_share,
                Err(err) => {
                    // TODO(brandon): is moving to Invalid on a decoding error appropriate?
                    // (may want to define a TransitionError for this, or decide to overload an existing one)
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, ?err, "Couldn't decode leader's input share");
                    report_aggregation.state = ReportAggregationState::Invalid;
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };

            // Initialize the leader's preparation state from the input share.
            let prep_state = match vdaf.prepare_init(
                &verify_param,
                &aggregation_job.aggregation_param,
                &report.nonce().get_encoded(),
                &leader_input_share,
            ) {
                Ok(prep_state) => prep_state,
                Err(err) => {
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, ?err, "Couldn't initialize leader's preparation state");
                    report_aggregation.state =
                        ReportAggregationState::Failed(TransitionError::VdafPrepError);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }
            };
            let leader_transition = vdaf.prepare_step(prep_state, None);
            if let PrepareTransition::Fail(err) = leader_transition {
                error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                    report_nonce = %report_aggregation.nonce, ?err, "Couldn't step leader's initial preparation state");
                report_aggregation.state =
                    ReportAggregationState::Failed(TransitionError::VdafPrepError);
                report_aggregations_to_write.push(report_aggregation);
                continue;
            };

            report_shares.push(ReportShare {
                nonce: report.nonce(),
                extensions: report.extensions().to_vec(),
                encrypted_input_share: helper_encrypted_input_share.clone(),
            });
            stepped_aggregations.push(SteppedAggregation {
                report_aggregation,
                leader_transition,
            });
        }

        // Construct request, and send it to the helper, and process the response.
        let req = AggregateReq {
            task_id: task.id,
            job_id: aggregation_job.aggregation_job_id,
            body: AggregateReqBody::AggregateInitReq {
                agg_param: aggregation_job.aggregation_param.get_encoded(),
                seq: report_shares,
            },
        };
        self.send_request_to_helper_and_complete_stepping(
            vdaf,
            task,
            aggregation_job,
            stepped_aggregations,
            report_aggregations_to_write,
            req,
        )
        .await
    }

    async fn step_aggregation_job_aggregate_continue<A: vdaf::Aggregator>(
        &self,
        vdaf: &A,
        task: Task,
        aggregation_job: AggregationJob<A>,
        report_aggregations: Vec<ReportAggregation<A>>,
    ) -> Result<()>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareStep: Send + Sync + Encode,
        A::PrepareMessage: Send + Sync,
    {
        // Visit the report aggregations, ignoring any that have already failed; compute our own
        // next step & transitions to send to the helper.
        let mut report_aggregations_to_write = Vec::new();
        let mut transitions = Vec::new();
        let mut stepped_aggregations = Vec::new();
        for mut report_aggregation in report_aggregations {
            if let ReportAggregationState::Waiting(prep_state, prep_msg) = &report_aggregation.state
            {
                let prep_msg = prep_msg
                    .as_ref()
                    .ok_or_else(|| anyhow!("report aggregation missing prepare message"))?;

                // Step our own state.
                let leader_transition =
                    vdaf.prepare_step(prep_state.clone(), Some(prep_msg.clone()));
                if let PrepareTransition::Fail(err) = leader_transition {
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, ?err, "Couldn't step report aggregation");
                    report_aggregation.state =
                        ReportAggregationState::Failed(TransitionError::VdafPrepError);
                    report_aggregations_to_write.push(report_aggregation);
                    continue;
                }

                transitions.push(Transition {
                    nonce: report_aggregation.nonce,
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: prep_msg.get_encoded(),
                    },
                });
                stepped_aggregations.push(SteppedAggregation {
                    report_aggregation,
                    leader_transition,
                })
            }
        }

        // Construct request, and send it to the helper, and process the response.
        let req = AggregateReq {
            task_id: task.id,
            job_id: aggregation_job.aggregation_job_id,
            body: AggregateReqBody::AggregateContinueReq { seq: transitions },
        };
        self.send_request_to_helper_and_complete_stepping(
            vdaf,
            task,
            aggregation_job,
            stepped_aggregations,
            report_aggregations_to_write,
            req,
        )
        .await
    }

    async fn send_request_to_helper_and_complete_stepping<A: vdaf::Aggregator>(
        &self,
        vdaf: &A,
        task: Task,
        aggregation_job: AggregationJob<A>,
        stepped_aggregations: Vec<SteppedAggregation<A>>,
        mut report_aggregations_to_write: Vec<ReportAggregation<A>>,
        req: AggregateReq,
    ) -> Result<()>
    where
        A: 'static,
        A::AggregationParam: Send + Sync,
        for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
        A::OutputShare: Send + Sync,
        for<'a> &'a A::OutputShare: Into<Vec<u8>>,
        A::PrepareMessage: Send + Sync,
        A::PrepareStep: Send + Sync + Encode,
    {
        // Send request to helper & parse the response.
        // TODO(brandon): what HTTP errors should cause us to abort/stop retrying the aggregation job?
        let key = task
            .primary_aggregator_auth_key()
            .ok_or_else(|| anyhow!("task has no aggregator auth keys"))?;
        let response = self
            .http_client
            .post(task.aggregator_url(Role::Helper)?.join("/aggregate")?)
            .body(AuthenticatedEncoder::new(req).encode(key.as_ref()))
            .send()
            .await?;
        let resp: AggregateResp = AuthenticatedResponseDecoder::new(response.bytes().await?)?
            .decode(task.agg_auth_keys.iter().map(|k| k.as_ref()).rev())?;

        // Handle response, computing the new report aggregations to be stored.
        if stepped_aggregations.len() != resp.seq.len() {
            return Err(anyhow!(
                "missing, duplicate, out-of-order, or unexpected transitions in response"
            ));
        }
        for (stepped_aggregation, helper_transition) in
            stepped_aggregations.into_iter().zip(resp.seq)
        {
            let (mut report_aggregation, leader_transition) = (
                stepped_aggregation.report_aggregation,
                stepped_aggregation.leader_transition,
            );
            if helper_transition.nonce != report_aggregation.nonce {
                return Err(anyhow!(
                    "missing, duplicate, out-of-order, or unexpected transitions in response"
                ));
            }
            match helper_transition.trans_data {
                TransitionTypeSpecificData::Continued { payload } => {
                    // If the leader continued too, combine the leader's message with the helper's
                    // and prepare to store the leader's new state & the combined message for the
                    // next round. If the leader didn't continue, transition to INVALID.
                    if let PrepareTransition::Continue(leader_prep_state, leader_prep_msg) =
                        leader_transition
                    {
                        // TODO(brandon): is it OK to match prep state w/ prep message decoding in
                        // this way? It works for the existing VDAFs, but I'm not sure if this is
                        // expected to be generally true.
                        let helper_prep_msg =
                            A::PrepareMessage::get_decoded_with_param(&leader_prep_state, &payload)
                                .context("couldn't decode helper's prepare message");
                        let combined_prep_msg = helper_prep_msg.and_then(|helper_prep_msg| {
                            vdaf.prepare_preprocess([leader_prep_msg, helper_prep_msg])
                                .context("couldn't combine leader & helper prepare messages")
                        });
                        report_aggregation.state = match combined_prep_msg {
                            Ok(combined_prep_msg) => ReportAggregationState::Waiting(
                                leader_prep_state,
                                Some(combined_prep_msg),
                            ),
                            Err(err) => {
                                error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                                    report_nonce = %report_aggregation.nonce, ?err, "Couldn't compute combined prepare message");
                                ReportAggregationState::Failed(TransitionError::VdafPrepError)
                            }
                        }
                    } else {
                        error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                            report_nonce = %report_aggregation.nonce, leader_transition = ?leader_transition, "Helper continued but leader did not");
                        report_aggregation.state = ReportAggregationState::Invalid;
                    }
                }

                TransitionTypeSpecificData::Finished => {
                    // If the leader finished too, we are done; prepare to store the output share.
                    // If the leader didn't finish too, we transition to INVALID.
                    if let PrepareTransition::Finish(out_share) = leader_transition {
                        report_aggregation.state = ReportAggregationState::Finished(out_share);
                    } else {
                        error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                            report_nonce = %report_aggregation.nonce, leader_transition = ?leader_transition, "Helper finished but leader did not");
                        report_aggregation.state = ReportAggregationState::Invalid;
                    }
                }

                TransitionTypeSpecificData::Failed { error } => {
                    // If the helper failed, we move to FAILED immediately.
                    // TODO(brandon): is it correct to just record the transition error that the helper reports?
                    error!(task_id = %task.id, aggregation_job_id = %aggregation_job.aggregation_job_id,
                        report_nonce = %report_aggregation.nonce, helper_err = ?error, "Helper couldn't step report aggregation");
                    report_aggregation.state = ReportAggregationState::Failed(error);
                }
            }
            report_aggregations_to_write.push(report_aggregation);
        }

        // Determine if we've finished the aggregation job (i.e. if all report aggregations are in
        // a terminal state), then write everything back to storage.
        let aggregation_job_id = aggregation_job.aggregation_job_id;
        let aggregation_job_is_finished = report_aggregations_to_write
            .iter()
            .all(|ra| !matches!(ra.state, ReportAggregationState::Waiting(_, _)));
        let aggregation_job_to_write = if aggregation_job_is_finished {
            let mut aggregation_job = aggregation_job;
            aggregation_job.state = AggregationJobState::Finished;
            Some(aggregation_job)
        } else {
            None
        };
        let report_aggregations_to_write = Arc::new(report_aggregations_to_write);
        let aggregation_job_to_write = Arc::new(aggregation_job_to_write);
        self.datastore
            .run_tx(|tx| {
                let (report_aggregations_to_write, aggregation_job_to_write) = (
                    Arc::clone(&report_aggregations_to_write),
                    Arc::clone(&aggregation_job_to_write),
                );
                Box::pin(async move {
                    let report_aggregations_future =
                        try_join_all(report_aggregations_to_write.iter().map(
                            |report_aggregation| tx.update_report_aggregation(report_aggregation),
                        ));
                    let aggregation_job_future = try_join_all(
                        aggregation_job_to_write
                            .iter()
                            .map(|aggregation_job| tx.update_aggregation_job(aggregation_job)),
                    );

                    try_join!(
                        tx.release_aggregation_job(task.id, aggregation_job_id),
                        report_aggregations_future,
                        aggregation_job_future
                    )?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    fn step_job_discovery_delay(&self, delay: Duration) -> Duration {
        // A zero delay is stepped to the configured minimum delay.
        if delay == Duration::ZERO {
            return self.min_aggregation_job_discovery_delay;
        }

        // Nonzero delays are doubled, up to the maximum configured delay.
        // (It's OK to use a saturating multiply here because the following min call causes us to
        // get the right answer even in the case we saturate.)
        let new_delay = Duration::from_seconds(delay.as_seconds().saturating_mul(2));
        let new_delay = Duration::min(new_delay, self.max_aggregation_job_discovery_delay);
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
                .saturating_sub(
                    self.aggregation_worker_lease_clock_skew_allowance
                        .as_seconds(),
                ),
        )
    }
}

/// SteppedAggregation represents a report aggregation along with the associated preparation-state
/// transition representing the next step for the leader.
struct SteppedAggregation<A: vdaf::Aggregator>
where
    for<'a> &'a A::AggregateShare: Into<Vec<u8>>,
{
    report_aggregation: ReportAggregation<A>,
    leader_transition: PrepareTransition<A::PrepareStep, A::PrepareMessage, A::OutputShare>,
}

#[cfg(test)]
mod tests {
    use crate::AggregationJobDriver;
    use assert_matches::assert_matches;
    use janus::{
        hpke::{
            self, associated_data_for_report_share,
            test_util::generate_hpke_config_and_private_key, HpkeApplicationInfo, Label,
        },
        message::{Duration, HpkeConfig, Nonce, Report, Role, TaskId},
        time::Clock,
    };
    use janus_server::{
        datastore::{
            models::{
                AggregationJob, AggregationJobState, ReportAggregation, ReportAggregationState,
            },
            Crypter, Datastore,
        },
        message::{
            AggregateReq, AggregateReqBody, AggregateResp, AggregationJobId, AuthenticatedEncoder,
            ReportShare, Transition, TransitionTypeSpecificData,
        },
        task::{test_util::new_dummy_task, VdafInstance},
        trace::test_util::install_test_trace_subscriber,
    };
    use mockito::mock;
    use prio::{
        codec::Encode,
        vdaf::{prio3::Prio3Aes128Count, PrepareTransition, Vdaf},
    };
    use reqwest::Url;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use test_util::{run_vdaf, MockClock};
    use tokio::{task, time};

    test_util::define_ephemeral_datastore!();

    #[tokio::test]
    async fn aggregation_job_driver() {
        // This is a minimal test that AggregationJobDriver::run() will successfully find
        // aggregation jobs & step them to completion. More detailed tests of the aggregation job
        // creation logic are contained in other tests which do not exercise the job-acquiry loop.
        // Note that we actually step twice to ensure that lease-release & re-acquiry works as
        // expected.

        // Setup.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let transcript = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameter = verify_params
            .get(Role::Leader.index().unwrap())
            .unwrap()
            .get_encoded();

        let agg_auth_key = task.primary_aggregator_auth_key().unwrap().clone();
        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &transcript.input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        ds.run_tx(|tx| {
            let (task, report) = (task.clone(), report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&report).await?;

                tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id,
                    aggregation_param: (),
                    state: AggregationJobState::InProgress,
                })
                .await?;
                tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id,
                    nonce: report.nonce(),
                    ord: 0,
                    state: ReportAggregationState::Start,
                })
                .await
            })
        })
        .await
        .unwrap();

        // Setup: prepare mocked HTTP responses.
        let helper_vdaf_msg = assert_matches!(&transcript.transitions[Role::Helper.index().unwrap()][0], PrepareTransition::Continue(_, prep_msg) => prep_msg);
        let helper_responses = vec![
            AggregateResp {
                seq: vec![Transition {
                    nonce,
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: helper_vdaf_msg.get_encoded(),
                    },
                }],
            },
            AggregateResp {
                seq: vec![Transition {
                    nonce,
                    trans_data: TransitionTypeSpecificData::Finished,
                }],
            },
        ];
        let next_helper_response_idx = AtomicUsize::new(0);
        let mocked_aggregate = mock("POST", "/aggregate")
            .with_status(200)
            .with_body_from_fn(move |w| {
                let idx = next_helper_response_idx.fetch_add(1, Ordering::SeqCst);
                let resp = helper_responses[idx].clone();
                let resp_bytes = AuthenticatedEncoder::new(resp).encode(agg_auth_key.as_ref());
                w.write_all(&resp_bytes)
            })
            .expect(2)
            .create();

        // Run. Give the aggregation job driver enough time to step aggregation jobs, then kill it.
        let aggregation_job_driver = Arc::new(AggregationJobDriver {
            datastore: ds,
            clock: clock.clone(),
            http_client: reqwest::Client::builder().build().unwrap(),
            min_aggregation_job_discovery_delay: Duration::from_seconds(1),
            max_aggregation_job_discovery_delay: Duration::from_seconds(1),
            max_concurrent_aggregation_job_workers: 10,
            aggregation_worker_lease_duration: Duration::from_seconds(600),
            aggregation_worker_lease_clock_skew_allowance: Duration::from_seconds(60),
        });
        let task_handle = task::spawn({
            let aggregation_job_driver = aggregation_job_driver.clone();
            async move { aggregation_job_driver.run().await }
        });

        // TODO(brandon): consider using tokio::time::pause() to make time deterministic, and allow
        // this test to run without the need for a (racy, wallclock-consuming) real sleep.
        // Unfortunately, at time of writing this TODO, calling time::pause() breaks interaction
        // with the database -- the job-acquiry transaction deadlocks on attempting to start a
        // transaction, even if the main test loops on calling yield_now().
        time::sleep(time::Duration::from_secs(5)).await;
        task_handle.abort();

        // Verify.
        mocked_aggregate.assert();

        let want_aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::Finished,
        };
        let leader_output_share = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][1], PrepareTransition::Finish(leader_output_share) => leader_output_share.clone());
        let want_report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Finished(leader_output_share),
        };

        let (got_aggregation_job, got_report_aggregation) = aggregation_job_driver
            .datastore
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await?
                        .unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
    }

    #[tokio::test]
    async fn step_aggregation_job_init() {
        // Setup: insert a client report and add it to a new aggregation job.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let transcript = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameter = leader_verify_param.get_encoded();

        let agg_auth_key = task.primary_aggregator_auth_key().unwrap();
        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &transcript.input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        ds.run_tx(|tx| {
            let (task, report) = (task.clone(), report.clone());
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&report).await?;

                tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id,
                    aggregation_param: (),
                    state: AggregationJobState::InProgress,
                })
                .await?;
                tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id,
                    nonce: report.nonce(),
                    ord: 0,
                    state: ReportAggregationState::Start,
                })
                .await
            })
        })
        .await
        .unwrap();

        // Setup: prepare mocked HTTP response.
        // TODO(brandon): this is fragile in that it expects the leader request to be
        // deterministically encoded. It would be nicer to retrieve the request bytes from the mock,
        // then do our own parsing & verification -- but mockito does not yet expose this
        // functionality.
        let leader_request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateReqBody::AggregateInitReq {
                agg_param: ().get_encoded(),
                seq: vec![ReportShare {
                    nonce,
                    extensions: Vec::new(),
                    encrypted_input_share: report
                        .encrypted_input_shares()
                        .get(Role::Helper.index().unwrap())
                        .unwrap()
                        .clone(),
                }],
            },
        };
        let helper_vdaf_msg = assert_matches!(&transcript.transitions[Role::Helper.index().unwrap()][0], PrepareTransition::Continue(_, prep_msg) => prep_msg);
        let helper_response = AggregateResp {
            seq: vec![Transition {
                nonce,
                trans_data: TransitionTypeSpecificData::Continued {
                    payload: helper_vdaf_msg.get_encoded(),
                },
            }],
        };
        let mocked_aggregate = mock("POST", "/aggregate")
            .match_body(AuthenticatedEncoder::new(leader_request).encode(agg_auth_key.as_ref()))
            .with_status(200)
            .with_body(AuthenticatedEncoder::new(helper_response).encode(agg_auth_key.as_ref()))
            .create();

        // Run: create an aggregation job driver & step the aggregation we've created.
        let aggregation_job_driver = AggregationJobDriver {
            datastore: ds,
            clock: clock.clone(),
            http_client: reqwest::Client::builder().build().unwrap(),
            min_aggregation_job_discovery_delay: Duration::from_seconds(10),
            max_aggregation_job_discovery_delay: Duration::from_seconds(60),
            max_concurrent_aggregation_job_workers: 10,
            aggregation_worker_lease_duration: Duration::from_seconds(600),
            aggregation_worker_lease_clock_skew_allowance: Duration::from_seconds(60),
        };
        aggregation_job_driver
            .step_aggregation_job(VdafInstance::Prio3Aes128Count, task_id, aggregation_job_id)
            .await
            .unwrap();

        // Verify.
        mocked_aggregate.assert();

        let want_aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::InProgress,
        };
        let leader_prep_state = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][0], PrepareTransition::Continue(prep_state, _) => prep_state.clone());
        let combined_prep_msg = transcript.combined_messages[0].clone();
        let want_report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Waiting(leader_prep_state, Some(combined_prep_msg)),
        };

        let (got_aggregation_job, got_report_aggregation) = aggregation_job_driver
            .datastore
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await?
                        .unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
    }

    #[tokio::test]
    async fn step_aggregation_job_continue() {
        // Setup: insert a client report and add it to an aggregation job whose state has already
        // been stepped once.
        install_test_trace_subscriber();
        let clock = MockClock::default();
        let (ds, _db_handle) = ephemeral_datastore(clock.clone()).await;
        let vdaf = Prio3Aes128Count::new(2).unwrap();
        let (public_param, verify_params) = vdaf.setup().unwrap();
        let leader_verify_param = verify_params.get(Role::Leader.index().unwrap()).unwrap();
        let nonce = Nonce::generate(&clock);
        let transcript = run_vdaf(&vdaf, &public_param, &verify_params, &(), nonce, &0);

        let task_id = TaskId::random();
        let mut task = new_dummy_task(task_id, VdafInstance::Prio3Aes128Count, Role::Leader);
        task.aggregator_endpoints = vec![
            Url::parse("http://irrelevant").unwrap(), // leader URL doesn't matter
            Url::parse(&mockito::server_url()).unwrap(),
        ];
        task.vdaf_verify_parameter = leader_verify_param.get_encoded();

        let agg_auth_key = task.primary_aggregator_auth_key().unwrap();
        let (leader_hpke_config, _) = task.hpke_keys.iter().next().unwrap().1;
        let (helper_hpke_config, _) = generate_hpke_config_and_private_key();
        let report = generate_report(
            task_id,
            nonce,
            &[leader_hpke_config, &helper_hpke_config],
            &transcript.input_shares,
        );
        let aggregation_job_id = AggregationJobId::random();

        let leader_prep_state = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][0], PrepareTransition::Continue(prep_state, _) => prep_state);
        let combined_msg = &transcript.combined_messages[0];

        ds.run_tx(|tx| {
            let (task, report, leader_prep_state, combined_msg) = (
                task.clone(),
                report.clone(),
                leader_prep_state.clone(),
                combined_msg.clone(),
            );
            Box::pin(async move {
                tx.put_task(&task).await?;
                tx.put_client_report(&report).await?;

                tx.put_aggregation_job(&AggregationJob::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id,
                    aggregation_param: (),
                    state: AggregationJobState::InProgress,
                })
                .await?;
                tx.put_report_aggregation(&ReportAggregation::<Prio3Aes128Count> {
                    aggregation_job_id,
                    task_id,
                    nonce: report.nonce(),
                    ord: 0,
                    state: ReportAggregationState::Waiting(leader_prep_state, Some(combined_msg)),
                })
                .await
            })
        })
        .await
        .unwrap();

        // Setup: prepare mocked HTTP response.
        // TODO(brandon): this is fragile in that it expects the leader request to be
        // deterministically encoded. It would be nicer to retrieve the request bytes from the mock,
        // then do our own parsing & verification -- but mockito does not yet expose this
        // functionality.
        let leader_request = AggregateReq {
            task_id,
            job_id: aggregation_job_id,
            body: AggregateReqBody::AggregateContinueReq {
                seq: vec![Transition {
                    nonce,
                    trans_data: TransitionTypeSpecificData::Continued {
                        payload: combined_msg.get_encoded(),
                    },
                }],
            },
        };
        let helper_response = AggregateResp {
            seq: vec![Transition {
                nonce,
                trans_data: TransitionTypeSpecificData::Finished,
            }],
        };
        let mocked_aggregate = mock("POST", "/aggregate")
            .match_body(AuthenticatedEncoder::new(leader_request).encode(agg_auth_key.as_ref()))
            .with_status(200)
            .with_body(AuthenticatedEncoder::new(helper_response).encode(agg_auth_key.as_ref()))
            .create();

        // Run: create an aggregation job driver & step the aggregation we've created.
        let aggregation_job_driver = AggregationJobDriver {
            datastore: ds,
            clock: clock.clone(),
            http_client: reqwest::Client::builder().build().unwrap(),
            min_aggregation_job_discovery_delay: Duration::from_seconds(10),
            max_aggregation_job_discovery_delay: Duration::from_seconds(60),
            max_concurrent_aggregation_job_workers: 10,
            aggregation_worker_lease_duration: Duration::from_seconds(600),
            aggregation_worker_lease_clock_skew_allowance: Duration::from_seconds(60),
        };
        aggregation_job_driver
            .step_aggregation_job(VdafInstance::Prio3Aes128Count, task_id, aggregation_job_id)
            .await
            .unwrap();

        // Verify.
        mocked_aggregate.assert();

        let want_aggregation_job = AggregationJob::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            aggregation_param: (),
            state: AggregationJobState::Finished,
        };
        let leader_output_share = assert_matches!(&transcript.transitions[Role::Leader.index().unwrap()][1], PrepareTransition::Finish(leader_output_share) => leader_output_share.clone());
        let want_report_aggregation = ReportAggregation::<Prio3Aes128Count> {
            aggregation_job_id,
            task_id,
            nonce,
            ord: 0,
            state: ReportAggregationState::Finished(leader_output_share),
        };

        let (got_aggregation_job, got_report_aggregation) = aggregation_job_driver
            .datastore
            .run_tx(|tx| {
                let leader_verify_param = leader_verify_param.clone();
                Box::pin(async move {
                    let aggregation_job = tx
                        .get_aggregation_job::<Prio3Aes128Count>(task_id, aggregation_job_id)
                        .await?
                        .unwrap();
                    let report_aggregation = tx
                        .get_report_aggregation::<Prio3Aes128Count>(
                            &leader_verify_param,
                            task_id,
                            aggregation_job_id,
                            nonce,
                        )
                        .await?
                        .unwrap();
                    Ok((aggregation_job, report_aggregation))
                })
            })
            .await
            .unwrap();

        assert_eq!(want_aggregation_job, got_aggregation_job);
        assert_eq!(want_report_aggregation, got_report_aggregation);
    }

    /// Returns a report with the given task ID & nonce values, no extensions, and encrypted input
    /// shares corresponding to the given HPKE configs & input shares.
    fn generate_report<I: Encode>(
        task_id: TaskId,
        nonce: Nonce,
        hpke_configs: &[&HpkeConfig],
        input_shares: &[I],
    ) -> Report {
        assert_eq!(hpke_configs.len(), 2);
        assert_eq!(input_shares.len(), 2);

        let encrypted_input_shares: Vec<_> = [Role::Leader, Role::Helper]
            .into_iter()
            .map(|role| {
                hpke::seal(
                    hpke_configs.get(role.index().unwrap()).unwrap(),
                    &HpkeApplicationInfo::new(task_id, Label::InputShare, Role::Client, role),
                    &input_shares
                        .get(role.index().unwrap())
                        .unwrap()
                        .get_encoded(),
                    &associated_data_for_report_share(nonce, &[]),
                )
            })
            .collect::<Result<_, _>>()
            .unwrap();

        Report::new(task_id, nonce, Vec::new(), encrypted_input_shares)
    }
}
