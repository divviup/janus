use std::{fmt::Debug, fs::File, path::PathBuf, process::exit, time::Duration as StdDuration};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{
    Args, CommandFactory, FromArgMatches, Parser, Subcommand,
    builder::{NonEmptyStringValueParser, StringValueParser, TypedValueParser},
    error::ErrorKind,
};
use janus_collector::{
    AuthenticationToken, Collection, CollectionJob, Collector, PollResult,
    PrivateCollectorCredential, default_http_client,
};
use janus_core::{
    hpke::{HpkeKeypair, HpkePrivateKey},
    retries::ExponentialWithTotalDelayBuilder,
    vdaf::VdafInstance,
    vdaf_dispatch,
};
use janus_messages::{
    BatchConfig, CollectionJobId, Duration, HpkeConfig, Interval, Query, TaskConfiguration, TaskId,
    Time, batch_mode::BatchMode,
};
use prio::{
    codec::Decode,
    vdaf::{self, Vdaf, VdafError},
};
use rand::random;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, Registry, prelude::*};

/// Enum to propagate errors through this program. Clap errors are handled separately from all
/// others because [`clap::Error::exit`] takes care of its own error formatting, command-line help,
/// and exit code.
#[derive(Debug)]
enum Error {
    Anyhow(anyhow::Error),
    Clap(clap::Error),
    PollNotReady,
}

impl Error {
    /// Corresponds to `EX_TEMPFAIL` on Unix-like systems.
    const POLL_NOT_READY_EXIT_STATUS: i32 = 75;
}

impl From<anyhow::Error> for Error {
    fn from(error: anyhow::Error) -> Self {
        Error::Anyhow(error)
    }
}

impl From<clap::Error> for Error {
    fn from(error: clap::Error) -> Self {
        Error::Clap(error)
    }
}

// `vdaf_dispatch!` applies `?` to the VDAF constructors it expands to.
impl From<VdafError> for Error {
    fn from(error: VdafError) -> Self {
        Error::Anyhow(error.into())
    }
}

// Parsers for command-line arguments:

#[derive(Clone)]
struct HpkeConfigValueParser {
    inner: NonEmptyStringValueParser,
}

impl HpkeConfigValueParser {
    fn new() -> HpkeConfigValueParser {
        HpkeConfigValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for HpkeConfigValueParser {
    type Value = HpkeConfig;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?;
        HpkeConfig::get_decoded(&bytes)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))
    }
}

#[derive(Clone)]
struct PrivateKeyValueParser {
    inner: NonEmptyStringValueParser,
}

impl PrivateKeyValueParser {
    fn new() -> PrivateKeyValueParser {
        PrivateKeyValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for PrivateKeyValueParser {
    type Value = HpkePrivateKey;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?;
        Ok(HpkePrivateKey::new(bytes))
    }
}

fn private_collector_credential_parser(
    s: &str,
) -> Result<PrivateCollectorCredential, serde_json::Error> {
    serde_json::from_str(s)
}

#[derive(Clone)]
struct TaskConfigurationValueParser {
    inner: NonEmptyStringValueParser,
}

impl TaskConfigurationValueParser {
    fn new() -> TaskConfigurationValueParser {
        TaskConfigurationValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for TaskConfigurationValueParser {
    type Value = TaskConfiguration;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?;
        TaskConfiguration::get_decoded(&bytes)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))
    }
}

#[derive(Debug, Args, PartialEq, Eq)]
struct AuthenticationOptions {
    /// Authentication token for the DAP-Auth-Token HTTP header
    #[clap(
        long,
        value_parser = StringValueParser::new().try_map(
            AuthenticationToken::new_dap_auth_token_from_string,
        ),
        env,
        hide_env_values = true,
        help_heading = "Authorization",
        display_order = 0,
        conflicts_with = "authorization_bearer_token"
    )]
    dap_auth_token: Option<AuthenticationToken>,

    /// Authentication token for the "Authorization: Bearer ..." HTTP header
    #[clap(
        long,
        value_parser = StringValueParser::new().try_map(
            AuthenticationToken::new_bearer_token_from_string,
        ),
        env,
        hide_env_values = true,
        help_heading = "Authorization",
        display_order = 1,
        conflicts_with = "dap_auth_token"
    )]
    authorization_bearer_token: Option<AuthenticationToken>,
}

#[derive(Debug, Args, PartialEq, Eq)]
struct QueryOptions {
    /// Start of the collection batch interval, as the number of seconds since the Unix epoch
    #[clap(
        long,
        requires = "batch_interval_duration",
        help_heading = "Collect Request Parameters (Time Interval)"
    )]
    batch_interval_start: Option<u64>,

    /// Duration of the collection batch interval, in seconds
    #[clap(
        long,
        requires = "batch_interval_start",
        help_heading = "Collect Request Parameters (Time Interval)"
    )]
    batch_interval_duration: Option<u64>,
}

#[derive(Debug, Args, PartialEq, Eq)]
#[group(required = true, multiple = true)]
struct HpkeConfigOptions {
    /// DAP message for the collector's HPKE configuration, encoded with base64url
    #[clap(
        long,
        value_parser = HpkeConfigValueParser::new(),
        help_heading = "HPKE Configuration",
        display_order = 0,
        requires = "hpke_private_key",
        conflicts_with_all = ["collector_credential_file", "collector_credential"]
    )]
    hpke_config: Option<HpkeConfig>,
    /// The collector's HPKE private key, encoded with base64url
    #[clap(
        long,
        value_parser = PrivateKeyValueParser::new(),
        env,
        hide_env_values = true,
        help_heading = "HPKE Configuration",
        display_order = 1,
        requires = "hpke_config",
        conflicts_with_all = ["collector_credential_file", "collector_credential"]
    )]
    hpke_private_key: Option<HpkePrivateKey>,
    /// Path to a file containing private collector credentials
    ///
    /// This can be obtained with the command `divviup collector-credential generate`.
    #[clap(
        long,
        help_heading = "HPKE Configuration",
        display_order = 2,
        conflicts_with_all = ["hpke_config", "hpke_private_key", "collector_credential"],
        visible_alias = "hpke-config-json",
    )]
    collector_credential_file: Option<PathBuf>,
    /// Private collector credentials
    ///
    /// This can be obtained with the command `divviup collector-credential generate`.
    #[clap(
        long,
        value_parser = private_collector_credential_parser,
        env,
        hide_env_values = true,
        help_heading = "HPKE Configuration",
        display_order = 3,
        conflicts_with_all = ["hpke_config", "hpke_private_key", "collector_credential_file"],
    )]
    collector_credential: Option<PrivateCollectorCredential>,
}

#[derive(Debug, PartialEq, Eq, Subcommand)]
enum Subcommands {
    /// Create a new collection job and poll it to completion
    ///
    /// This is the default action when no subcommand is provided.
    Run,
    /// Initialize a new collection job
    ///
    /// Outputs collection job ID to stdout.
    NewJob {
        /// Job ID to use for the new collection job. If absent, an ID is randomly generated
        ///
        /// A valid ID consists of 16 randomly selected bytes, encoded with unpadded base64url.
        collection_job_id: Option<CollectionJobId>,
    },
    /// Poll an existing collection job once
    ///
    /// The supplied query options must exactly match the ones used to create the collection job,
    /// so that the collection job state can be correctly reconstructed.
    ///
    /// If the collection job is ready, the exit status is 0 and the job results are output to
    /// stdout. If it is not ready, the exit status is 75 (EX_TEMPFAIL).
    PollJob {
        /// Job ID for an existing collection job, encoded with unpadded base64url
        #[clap(required = true)]
        collection_job_id: CollectionJobId,
    },
}

#[derive(Debug, Parser, PartialEq, Eq)]
#[clap(
    name = "collect",
    version,
    about = "Command-line DAP-PPM collector from ISRG's Divvi Up",
    long_about = concat!(
        "Command-line DAP-PPM collector from ISRG's Divvi Up\n\n",
        "The default subcommand is \"run\", which will create a collection job and poll it to ",
        "completion",
    ),
)]
struct Options {
    #[clap(subcommand)]
    subcommand: Option<Subcommands>,

    /// DAP task identifier, encoded with unpadded base64url
    #[clap(long, help_heading = "DAP Task Parameters", display_order = 0)]
    task_id: TaskId,
    /// The task's DAP TaskConfiguration message, encoded with unpadded base64url
    ///
    /// This supplies the aggregator endpoints, time precision, batch configuration, and VDAF
    /// configuration. Its bytes are bound into the HPKE additional authenticated data, so it must
    /// be exactly the message the aggregators were provisioned with.
    #[clap(
        long,
        value_parser = TaskConfigurationValueParser::new(),
        help_heading = "DAP Task Parameters",
        display_order = 1
    )]
    task_config: TaskConfiguration,

    #[clap(flatten)]
    authentication: AuthenticationOptions,

    #[clap(flatten)]
    hpke_config: HpkeConfigOptions,

    #[clap(flatten)]
    query: QueryOptions,
}

impl Options {
    fn collector_credential(&self) -> Result<Option<PrivateCollectorCredential>, Error> {
        match (
            &self.hpke_config.collector_credential,
            &self.hpke_config.collector_credential_file,
        ) {
            (Some(collector_credential), None) => Ok(Some(collector_credential.clone())),
            (None, Some(collector_credential_file)) => {
                let reader = File::open(collector_credential_file)
                    .context("could not open HPKE config file")?;
                Ok(Some(
                    serde_json::from_reader(reader).context("could not parse HPKE config file")?,
                ))
            }
            (None, None) => Ok(None),
            (Some(_), Some(_)) => {
                unreachable!("collector credential arguments are mutually exclusive")
            }
        }
    }

    fn authentication_token(
        &self,
        collector_credential: Option<&PrivateCollectorCredential>,
    ) -> Option<AuthenticationToken> {
        match (
            &self.authentication.dap_auth_token,
            &self.authentication.authorization_bearer_token,
            collector_credential,
        ) {
            // Prioritize tokens provided via CLI arguments.
            (Some(token), None, _) => Some(token.clone()),
            (None, Some(token), _) => Some(token.clone()),
            // Fall back to collector credential token, if present.
            (None, None, Some(collector_credential)) => {
                Some(collector_credential.authentication_token())
            }
            (None, None, None) => None,
            _ => unreachable!("all authentication token arguments are mutually exclusive"),
        }
    }

    fn hpke_keypair(
        &self,
        collector_credential: Option<&PrivateCollectorCredential>,
    ) -> Result<HpkeKeypair, anyhow::Error> {
        match (
            &self.hpke_config.hpke_config,
            &self.hpke_config.hpke_private_key,
            collector_credential,
        ) {
            (Some(config), Some(private), None) => {
                Ok(HpkeKeypair::new(config.clone(), private.clone()))
            }
            (None, None, Some(collector_credential)) => Ok(collector_credential.hpke_keypair()),
            _ => unreachable!(
                "hpke arguments are mutually exclusive with collector credential arguments"
            ),
        }
    }

    /// Extract all collector-related credentials from the given options.
    fn credential(&self) -> Result<(AuthenticationToken, HpkeKeypair), Error> {
        let collector_credential = self.collector_credential()?;
        let authentication_token = self
            .authentication_token(collector_credential.as_ref())
            .ok_or_else(|| {
                clap::Error::raw(
                    ErrorKind::MissingRequiredArgument,
                    "no authentication token was provided",
                )
            })?;
        Ok((
            authentication_token,
            self.hpke_keypair(collector_credential.as_ref())?,
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_tracing_subscriber()?;

    let mut command = Options::command();
    let mut matches = match command.try_get_matches_from_mut(std::env::args_os()) {
        Ok(matches) => matches,
        Err(err) => err.format(&mut command).exit(),
    };
    let options = match Options::from_arg_matches_mut(&mut matches) {
        Ok(options) => options,
        Err(err) => err.format(&mut command).exit(),
    };

    match run(options).await {
        Ok(()) => Ok(()),
        Err(Error::Anyhow(err)) => Err(err),
        Err(Error::Clap(err)) => err.format(&mut command).exit(),
        Err(Error::PollNotReady) => exit(Error::POLL_NOT_READY_EXIT_STATUS),
    }
}

/// The batch to collect, resolved against the task's batch configuration.
enum ResolvedQuery {
    TimeInterval(Interval),
    LeaderSelected,
}

/// Resolves the query arguments against the batch configuration in `--task-config`. The batch mode
/// comes from the task configuration and the batch interval from the command line, so clap cannot
/// rule out a disagreement between them.
fn resolve_query(options: &Options) -> Result<ResolvedQuery, Error> {
    let batch_config = options.task_config.batch_config();
    match (
        batch_config,
        options.query.batch_interval_start,
        options.query.batch_interval_duration,
    ) {
        (BatchConfig::TimeInterval, Some(start), Some(duration)) => {
            let time_precision = options.task_config.time_precision();
            Ok(ResolvedQuery::TimeInterval(
                Interval::new(
                    Time::from_seconds_since_epoch(start, time_precision),
                    Duration::from_seconds(duration, time_precision),
                )
                .map_err(|err| Error::Anyhow(err.into()))?,
            ))
        }
        (BatchConfig::TimeInterval, None, None) => Err(clap::Error::raw(
            ErrorKind::MissingRequiredArgument,
            "the task is a time-interval task, so --batch-interval-start and \
             --batch-interval-duration are required\n",
        )
        .into()),
        (BatchConfig::TimeInterval, _, _) => {
            unreachable!("clap requires both batch interval arguments together")
        }
        (BatchConfig::LeaderSelected, None, None) => Ok(ResolvedQuery::LeaderSelected),
        (BatchConfig::LeaderSelected, _, _) => Err(clap::Error::raw(
            ErrorKind::ArgumentConflict,
            "the task is a leader-selected task, so --batch-interval-start and \
             --batch-interval-duration must not be provided\n",
        )
        .into()),
        (batch_config, _, _) => Err(clap::Error::raw(
            ErrorKind::ValueValidation,
            format!(
                "unsupported batch mode in --task-config: {}\n",
                batch_config.batch_mode()
            ),
        )
        .into()),
    }
}

macro_rules! options_query_dispatch {
    ($options:expr, ($query:ident) => $body:tt) => {
        match resolve_query(&$options)? {
            ResolvedQuery::TimeInterval(batch_interval) => {
                let $query = Query::new_time_interval(batch_interval);
                $body
            }
            ResolvedQuery::LeaderSelected => {
                let $query = Query::new_leader_selected();
                $body
            }
        }
    };
}

macro_rules! options_vdaf_dispatch {
    ($options:expr, ($vdaf:ident) => $body:tt) => {{
        let vdaf_instance = VdafInstance::try_from($options.task_config.vdaf_config())
            .map_err(|err| {
                clap::Error::raw(
                    ErrorKind::ValueValidation,
                    format!("unsupported VDAF in --task-config: {err}\n"),
                )
            })?;
        vdaf_dispatch!(&vdaf_instance, ($vdaf, VdafType, _VERIFY_KEY_LEN) => {
            // The multiproof VDAF's constructor is generic over its gadget, so pin the arm's
            // concrete type rather than leaving it to inference at the call sites.
            let $vdaf: VdafType = $vdaf;
            $body
        })
    }};
}

macro_rules! options_dispatch {
    ($options:expr, ($query:ident, $vdaf:ident) => $body:tt) => {
        options_query_dispatch!($options, ($query) => {
            options_vdaf_dispatch!($options, ($vdaf) =>
                $body
            )
        })
    }
}

// This function is broken out from `main()` for the sake of testing its argument handling.
async fn run(options: Options) -> Result<(), Error> {
    let http_client = default_http_client().map_err(|err| Error::Anyhow(err.into()))?;
    options_dispatch!(options, (query, vdaf) => {
        // Every VDAF this tool dispatches to has a trivial aggregation parameter.
        let agg_param: &<VdafType as Vdaf>::AggregationParam = &Default::default();
        match options.subcommand {
            Some(Subcommands::NewJob { collection_job_id }) => {
                let collection_job_id = collection_job_id.unwrap_or_else(random);
                run_new_job(options, vdaf, http_client, query, agg_param, collection_job_id).await
            }
            Some(Subcommands::PollJob { collection_job_id }) => {
                run_poll_job(options, vdaf, http_client, query, agg_param, collection_job_id).await
            }
            _ => run_collection(options, vdaf, http_client, query, agg_param).await,
        }
    })
}

async fn run_collection<V: vdaf::Collector, B: BatchMode>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<B>,
    agg_param: &V::AggregationParam,
) -> Result<(), Error>
where
    V::AggregateResult: Debug,
{
    let collection = new_collector(options, vdaf, http_client)?
        .collection(query, agg_param)
        .collect()
        .await
        .map_err(|err| Error::Anyhow(err.into()))?;
    print_collection::<V, B>(collection)?;
    Ok(())
}

async fn run_new_job<V: vdaf::Collector, B: BatchMode>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<B>,
    agg_param: &V::AggregationParam,
    collection_job_id: CollectionJobId,
) -> Result<(), Error>
where
    V::AggregateResult: Debug,
{
    let collection = new_collector(options, vdaf, http_client)?
        .collection(query, agg_param)
        .with_id(collection_job_id)
        .start()
        .await
        .map_err(|err| Error::Anyhow(err.into()))?;
    println!("Job ID: {}", collection.collection_job_id());
    Ok(())
}

async fn run_poll_job<V: vdaf::Collector, B: BatchMode>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<B>,
    agg_param: &V::AggregationParam,
    collection_job_id: CollectionJobId,
) -> Result<(), Error>
where
    V::AggregateResult: Debug,
{
    let collection_job = CollectionJob::new(collection_job_id, query, agg_param.clone());
    let poll_result = new_collector(options, vdaf, http_client)?
        .poll_once(&collection_job)
        .await
        .map_err(|err| Error::Anyhow(err.into()))?;
    match poll_result {
        PollResult::CollectionResult(collection) => {
            println!("State: Ready");
            print_collection::<V, B>(collection)?;
            Ok(())
        }
        PollResult::NotReady(retry_after) => {
            println!("State: Not ready");
            match retry_after {
                Some(retry_after) => println!("Retry after: {retry_after:?}"),
                None => println!("Retry after: Not provided"),
            }
            Err(Error::PollNotReady)
        }
    }
}

fn new_collector<V: vdaf::Collector>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
) -> Result<Collector<V>, Error> {
    let (authentication, hpke_keypair) = options.credential()?;
    let task_config = options.task_config;
    let collector = Collector::builder_with_custom_vdaf(
        options.task_id,
        authentication,
        hpke_keypair,
        vdaf,
        task_config.vdaf_config().clone(),
    )
    .with_task_configuration(task_config)
    .with_http_client(http_client)
    .with_collect_poll_backoff(
        ExponentialWithTotalDelayBuilder::new()
            .with_min_delay(StdDuration::from_secs(3))
            .with_max_delay(StdDuration::from_secs(300))
            .with_factor(1.2)
            .with_max_times(10)
            .with_jitter(),
    )
    .build()
    .map_err(|err| Error::Anyhow(err.into()))?;
    Ok(collector)
}

fn print_collection<V: vdaf::Collector, B: BatchMode>(
    collection: Collection<<V as Vdaf>::AggregateResult, B>,
) -> Result<(), Error> {
    let (start, duration) = collection.interval();

    println!("Number of reports: {}", collection.report_count());
    println!("Interval start: {start}");
    println!("Interval end: {}", *start + *duration);
    println!(
        "Interval length: {:?}",
        // `std::time::Duration` has the most human-readable debug print for a Duration.
        duration.to_std().map_err(|err| Error::Anyhow(err.into()))?
    );
    println!("Aggregation result: {:?}", collection.aggregate_result());
    Ok(())
}

fn install_tracing_subscriber() -> anyhow::Result<()> {
    let stdout_filter = EnvFilter::builder().from_env()?;
    let layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .pretty();
    let subscriber = Registry::default().with(stdout_filter.and_then(layer));
    tracing::subscriber::set_global_default(subscriber)?;

    LogTracer::init()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use assert_matches::assert_matches;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use clap::{CommandFactory, Parser, error::ErrorKind};
    use janus_collector::PrivateCollectorCredential;
    use janus_core::{
        auth_tokens::{BearerToken, DapAuthToken},
        hpke::HpkeKeypair,
        initialize_rustls,
        test_util::install_test_trace_subscriber,
    };
    use janus_messages::{BatchConfig, TaskConfiguration, TaskId, TimePrecision, VdafConfig};
    use prio::{codec::Encode, vdaf::prio3::Prio3};
    use rand::random;
    use tempfile::NamedTempFile;

    use crate::{
        AuthenticationOptions, AuthenticationToken, Error, HpkeConfigOptions, Options,
        QueryOptions, Subcommands, default_http_client, new_collector, run,
    };

    const SAMPLE_COLLECTOR_CREDENTIAL: &str = r#"{
  "aead": "AesGcm128",
  "id": 66,
  "kdf": "Sha256",
  "kem": "X25519HkdfSha256",
  "private_key": "uKkTvzKLfYNUPZcoKI7hV64zS06OWgBkbivBL4Sw4mo",
  "public_key": "CcDghts2boltt9GQtBUxdUsVR83SCVYHikcGh33aVlU",
  "token": "Krx-CLfdWo1ULAfsxhr0rA"
}
"#;

    const LEADER_ENDPOINT: &str = "https://example.com/dap/";

    fn task_config(batch_config: BatchConfig) -> TaskConfiguration {
        TaskConfiguration::new(
            b"test task".to_vec(),
            LEADER_ENDPOINT.try_into().unwrap(),
            "https://helper.example.com/dap/".try_into().unwrap(),
            TimePrecision::from_seconds(300),
            100,
            batch_config,
            VdafConfig::Prio3Count,
            Vec::new(),
        )
        .unwrap()
    }

    fn task_config_argument(batch_config: BatchConfig) -> String {
        format!(
            "--task-config={}",
            URL_SAFE_NO_PAD.encode(task_config(batch_config).get_encoded().unwrap())
        )
    }

    #[test]
    fn verify_app() {
        Options::command().debug_assert();
    }

    #[tokio::test]
    async fn argument_handling() {
        install_test_trace_subscriber();
        initialize_rustls();

        let hpke_keypair = HpkeKeypair::test();
        let encoded_hpke_config =
            URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let task_id = random();
        let auth_token = AuthenticationToken::DapAuth(random());

        let expected = Options {
            subcommand: None,
            task_id,
            task_config: task_config(BatchConfig::TimeInterval),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: HpkeConfigOptions {
                hpke_config: Some(hpke_keypair.config().clone()),
                hpke_private_key: Some(hpke_keypair.private_key().clone()),
                collector_credential_file: None,
                collector_credential: None,
            },
            query: QueryOptions {
                batch_interval_start: Some(1_000_000),
                batch_interval_duration: Some(1_000),
            },
        };
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());
        let task_config_argument = task_config_argument(BatchConfig::TimeInterval);
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            &task_config_argument,
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{e}\narguments were {correct_arguments:?}"),
        }

        assert_eq!(
            Options::try_parse_from(["collect"]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument,
        );

        // Missing HPKE configuration entirely.
        assert_eq!(
            Options::try_parse_from([
                "collect",
                &format!("--task-id={task_id_encoded}"),
                &task_config_argument,
                &format!("--dap-auth-token={}", auth_token.as_str()),
                "--batch-interval-start",
                "1000000",
                "--batch-interval-duration",
                "1000",
            ])
            .unwrap_err()
            .kind(),
            ErrorKind::MissingRequiredArgument,
        );

        // Missing the task configuration entirely.
        assert_eq!(
            Options::try_parse_from([
                "collect",
                &format!("--task-id={task_id_encoded}"),
                &format!("--dap-auth-token={}", auth_token.as_str()),
                &format!("--hpke-config={encoded_hpke_config}"),
                &format!("--hpke-private-key={encoded_private_key}"),
            ])
            .unwrap_err()
            .kind(),
            ErrorKind::MissingRequiredArgument,
        );

        let mut bad_arguments = correct_arguments;
        bad_arguments[1] = "--task-id=not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments;
        let short_encoded = URL_SAFE_NO_PAD.encode("too short");
        let bad_argument = format!("--task-id={short_encoded}");
        bad_arguments[1] = &bad_argument;
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments;
        bad_arguments[2] = "--task-config=not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        // A truncated task configuration: valid base64url, but not a decodable message.
        let mut bad_arguments = correct_arguments;
        let truncated = task_config(BatchConfig::TimeInterval)
            .get_encoded()
            .unwrap();
        let bad_argument = format!(
            "--task-config={}",
            URL_SAFE_NO_PAD.encode(&truncated[..truncated.len() / 2])
        );
        bad_arguments[2] = &bad_argument;
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments;
        bad_arguments[4] = "--hpke-config=not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments;
        bad_arguments[5] = "--hpke-private-key=not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );
    }

    /// The collector's task parameters are all resolved from the task configuration at build time,
    /// so a wiring mistake in `new_collector` would fail every real invocation while leaving the
    /// argument-parsing tests green.
    #[test]
    fn new_collector_accepts_task_config() {
        install_test_trace_subscriber();
        initialize_rustls();

        let hpke_keypair = HpkeKeypair::test();
        let task_id: TaskId = random();
        let auth_token = AuthenticationToken::DapAuth(random());
        let options = Options::try_parse_from([
            "collect".to_string(),
            format!(
                "--task-id={}",
                URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap())
            ),
            task_config_argument(BatchConfig::TimeInterval),
            format!("--dap-auth-token={}", auth_token.as_str()),
            format!(
                "--hpke-config={}",
                URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap())
            ),
            format!(
                "--hpke-private-key={}",
                URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref())
            ),
            "--batch-interval-start=1000000".to_string(),
            "--batch-interval-duration=1000".to_string(),
        ])
        .unwrap();

        new_collector(
            options,
            Prio3::new_count(2).unwrap(),
            default_http_client().unwrap(),
        )
        .unwrap();
    }

    /// The task configuration states the batch mode and the command line selects the batch, so
    /// clap cannot rule out a disagreement between them.
    #[tokio::test]
    async fn query_must_match_batch_config() {
        install_test_trace_subscriber();
        initialize_rustls();

        let hpke_keypair = HpkeKeypair::test();
        let task_id: TaskId = random();
        let auth_token = AuthenticationToken::DapAuth(random());
        let base_arguments = Vec::from([
            "collect".to_string(),
            format!(
                "--task-id={}",
                URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap())
            ),
            format!("--dap-auth-token={}", auth_token.as_str()),
            format!(
                "--hpke-config={}",
                URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap())
            ),
            format!(
                "--hpke-private-key={}",
                URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref())
            ),
        ]);

        // A time-interval task with no batch interval.
        let mut arguments = base_arguments.clone();
        arguments.push(task_config_argument(BatchConfig::TimeInterval));
        let options = Options::try_parse_from(arguments).unwrap();
        assert_matches!(
            run(options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument)
        );

        // A leader-selected task with a batch interval.
        let mut arguments = base_arguments;
        arguments.extend([
            task_config_argument(BatchConfig::LeaderSelected),
            "--batch-interval-start=1000000".to_string(),
            "--batch-interval-duration=1000".to_string(),
        ]);
        let options = Options::try_parse_from(arguments).unwrap();
        assert_matches!(
            run(options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
        );
    }

    #[test]
    fn batch_arguments() {
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());

        let hpke_keypair = HpkeKeypair::test();
        let encoded_hpke_config =
            URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());
        let auth_token = AuthenticationToken::DapAuth(random());
        let task_config_argument = task_config_argument(BatchConfig::LeaderSelected);

        // Check parsing arguments for a leader-selected query.
        let expected = Options {
            subcommand: None,
            task_id,
            task_config: task_config(BatchConfig::LeaderSelected),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: HpkeConfigOptions {
                hpke_config: Some(hpke_keypair.config().clone()),
                hpke_private_key: Some(hpke_keypair.private_key().clone()),
                collector_credential_file: None,
                collector_credential: None,
            },
            query: QueryOptions {
                batch_interval_start: None,
                batch_interval_duration: None,
            },
        };
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            &task_config_argument,
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{e}\narguments were {correct_arguments:?}"),
        }

        // Clap requires the two batch interval arguments together, which is what lets
        // `resolve_query` treat a lone one as unreachable.
        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            task_config_argument,
            format!("--dap-auth-token={}", auth_token.as_str()),
            format!("--hpke-config={encoded_hpke_config}"),
            format!("--hpke-private-key={encoded_private_key}"),
        ]);

        Options::try_parse_from(base_arguments.clone()).unwrap();

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.push("--batch-interval-start=1".to_string());
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.push("--batch-interval-duration=1".to_string());
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn auth_arguments() {
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());

        let hpke_keypair = HpkeKeypair::test();
        let encoded_hpke_config =
            URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            task_config_argument(BatchConfig::TimeInterval),
            format!("--hpke-config={encoded_hpke_config}"),
            format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
        ]);

        let dap_auth_token: DapAuthToken = random();
        let bearer_token: BearerToken = random();

        let dap_auth_token_argument = format!("--dap-auth-token={}", dap_auth_token.as_str());
        let authorization_bearer_token_argument =
            format!("--authorization-bearer-token={}", bearer_token.as_str());

        let mut case_1_arguments = base_arguments.clone();
        case_1_arguments.push(dap_auth_token_argument.clone());
        let (authentication_token, _) = Options::try_parse_from(case_1_arguments)
            .unwrap()
            .credential()
            .unwrap();
        assert_eq!(
            authentication_token,
            AuthenticationToken::DapAuth(dap_auth_token),
        );

        let mut case_2_arguments = base_arguments.clone();
        case_2_arguments.push(authorization_bearer_token_argument.clone());
        let (authentication_token, _) = Options::try_parse_from(case_2_arguments)
            .unwrap()
            .credential()
            .unwrap();
        assert_eq!(
            authentication_token,
            AuthenticationToken::Bearer(bearer_token),
        );

        let mut case_4_arguments = base_arguments.clone();
        case_4_arguments.push(dap_auth_token_argument);
        case_4_arguments.push(authorization_bearer_token_argument);
        assert_eq!(
            Options::try_parse_from(case_4_arguments)
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict
        );

        let mut case_5_arguments = base_arguments;
        case_5_arguments.push("--authorization-bearer-token=not-base-64-!@#$%^&*".to_string());
        assert_eq!(
            Options::try_parse_from(case_5_arguments)
                .unwrap_err()
                .kind(),
            ErrorKind::ValueValidation
        );
    }

    #[test]
    fn collector_credential_file() {
        let collector_credential =
            serde_json::from_str::<PrivateCollectorCredential>(SAMPLE_COLLECTOR_CREDENTIAL)
                .unwrap();

        let mut collector_credential_file = NamedTempFile::new().unwrap();
        collector_credential_file
            .write_all(SAMPLE_COLLECTOR_CREDENTIAL.as_bytes())
            .unwrap();
        let collector_credential_file_path = collector_credential_file.into_temp_path();

        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());
        let bearer_token: BearerToken = random();
        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            task_config_argument(BatchConfig::TimeInterval),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
        ]);

        // Missing all credential args entirely.
        assert_eq!(
            Options::try_parse_from(base_arguments.clone())
                .unwrap_err()
                .kind(),
            ErrorKind::MissingRequiredArgument
        );

        let mut arguments = base_arguments.clone();
        arguments.push(format!(
            "--collector-credential-file={}",
            collector_credential_file_path.to_string_lossy(),
        ));
        assert_eq!(
            Options::try_parse_from(arguments.clone())
                .unwrap()
                .credential()
                .unwrap(),
            (
                collector_credential.authentication_token(),
                collector_credential.hpke_keypair()
            ),
        );

        // Should prioritize any tokens provided via CLI arguments.
        arguments.push(format!(
            "--authorization-bearer-token={}",
            bearer_token.as_str()
        ));
        assert_eq!(
            Options::try_parse_from(arguments)
                .unwrap()
                .credential()
                .unwrap(),
            (
                AuthenticationToken::Bearer(bearer_token.clone()),
                collector_credential.hpke_keypair()
            ),
        );

        let mut backcompat_arguments = base_arguments.clone();
        backcompat_arguments.push(format!(
            "--hpke-config-json={}",
            collector_credential_file_path.to_string_lossy(),
        ));
        assert_eq!(
            Options::try_parse_from(backcompat_arguments)
                .unwrap()
                .credential()
                .unwrap(),
            (
                collector_credential.authentication_token(),
                collector_credential.hpke_keypair()
            ),
        );
    }

    #[test]
    fn collector_credential() {
        let collector_credential =
            serde_json::from_str::<PrivateCollectorCredential>(SAMPLE_COLLECTOR_CREDENTIAL)
                .unwrap();
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());
        let bearer_token: BearerToken = random();

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            task_config_argument(BatchConfig::TimeInterval),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
            format!("--authorization-bearer-token={}", bearer_token.as_str()),
            format!("--collector-credential={SAMPLE_COLLECTOR_CREDENTIAL}"),
        ]);

        assert_eq!(
            Options::try_parse_from(base_arguments)
                .unwrap()
                .hpke_config
                .collector_credential
                .unwrap(),
            collector_credential,
        );
    }

    #[test]
    fn hpke_config() {
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());
        let hpke_keypair = HpkeKeypair::test();
        let encoded_hpke_config =
            URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());
        let auth_token = AuthenticationToken::DapAuth(random());

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            task_config_argument(BatchConfig::TimeInterval),
            format!("--dap-auth-token={}", auth_token.as_str()),
        ]);

        let mut correct_arguments = base_arguments.clone();
        correct_arguments.extend([
            format!("--hpke-config={encoded_hpke_config}"),
            format!("--hpke-private-key={encoded_private_key}"),
        ]);
        let (_, got_hpke_keypair) = Options::try_parse_from(correct_arguments.clone())
            .unwrap()
            .credential()
            .unwrap();
        assert_eq!(hpke_keypair, got_hpke_keypair);

        let mut missing_config = base_arguments.clone();
        missing_config.push(format!("--hpke-private-key={encoded_private_key}"));
        assert_eq!(
            Options::try_parse_from(missing_config).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument,
        );

        let mut missing_key = base_arguments.clone();
        missing_key.push(format!("--hpke-config={encoded_hpke_config}"));
        assert_eq!(
            Options::try_parse_from(missing_key).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument,
        );

        let mut collector_credential_mutually_exclusive = correct_arguments.clone();
        collector_credential_mutually_exclusive.push(format!(
            "--collector-credential={SAMPLE_COLLECTOR_CREDENTIAL}",
        ));
        assert_eq!(
            Options::try_parse_from(collector_credential_mutually_exclusive)
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict,
        );

        let mut collector_credential_file_mutually_exclusive = correct_arguments.clone();
        collector_credential_file_mutually_exclusive
            .push("--collector-credential-file=foo".to_string());
        assert_eq!(
            Options::try_parse_from(collector_credential_file_mutually_exclusive)
                .unwrap_err()
                .kind(),
            ErrorKind::ArgumentConflict,
        );
    }

    #[test]
    fn subcommand_new_job_arguments() {
        let hpke_keypair = HpkeKeypair::test();
        let encoded_hpke_config =
            URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let task_id = random();
        let auth_token = AuthenticationToken::DapAuth(random());
        let task_config_argument = task_config_argument(BatchConfig::TimeInterval);

        let mut expected = Options {
            subcommand: Some(Subcommands::NewJob {
                collection_job_id: None,
            }),
            task_id,
            task_config: task_config(BatchConfig::TimeInterval),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: HpkeConfigOptions {
                hpke_config: Some(hpke_keypair.config().clone()),
                hpke_private_key: Some(hpke_keypair.private_key().clone()),
                collector_credential_file: None,
                collector_credential: None,
            },
            query: QueryOptions {
                batch_interval_start: Some(1_000_000),
                batch_interval_duration: Some(1_000),
            },
        };
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            &task_config_argument,
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
            "new-job",
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{e}\narguments were {correct_arguments:?}"),
        }

        let collection_job_id = random();
        expected.subcommand = Some(Subcommands::NewJob {
            collection_job_id: Some(collection_job_id),
        });
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            &task_config_argument,
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
            "new-job",
            "--", // prevent ID from being interpreted as a flag, in case it starts with a hyphen.
            &format!("{collection_job_id}"),
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{e}\narguments were {correct_arguments:?}"),
        }
    }

    #[test]
    fn subcommand_poll_job_arguments() {
        let hpke_keypair = HpkeKeypair::test();
        let encoded_hpke_config =
            URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded().unwrap());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let task_id = random();
        let auth_token = AuthenticationToken::DapAuth(random());
        let task_config_argument = task_config_argument(BatchConfig::TimeInterval);
        let collection_job_id = random();
        let expected = Options {
            subcommand: Some(Subcommands::PollJob { collection_job_id }),
            task_id,
            task_config: task_config(BatchConfig::TimeInterval),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: HpkeConfigOptions {
                hpke_config: Some(hpke_keypair.config().clone()),
                hpke_private_key: Some(hpke_keypair.private_key().clone()),
                collector_credential_file: None,
                collector_credential: None,
            },
            query: QueryOptions {
                batch_interval_start: Some(1_000_000),
                batch_interval_duration: Some(1_000),
            },
        };
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded().unwrap());
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            &task_config_argument,
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
            "poll-job",
            "--", // prevent ID from being interpreted as a flag, in case it starts with a hyphen.
            &collection_job_id.to_string(),
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{e}\narguments were {correct_arguments:?}"),
        }

        let mut bad_arguments = correct_arguments;
        bad_arguments[bad_arguments.len() - 1] = "invalid";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );
    }
}
