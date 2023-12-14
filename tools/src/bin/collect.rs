use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{
    builder::{NonEmptyStringValueParser, StringValueParser, TypedValueParser},
    error::ErrorKind,
    ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum,
};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32};
use janus_collector::{
    default_http_client, AuthenticationToken, Collection, CollectionJob, Collector,
    ExponentialBackoff, PollResult, PrivateCollectorCredential,
};
use janus_core::hpke::{HpkeKeypair, HpkePrivateKey};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    BatchId, CollectionJobId, Duration, FixedSizeQuery, HpkeConfig, Interval, PartialBatchSelector,
    Query, TaskId, Time,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
use prio::{
    codec::Decode,
    vdaf::{self, prio3::Prio3, Vdaf},
};
use rand::random;
use std::{fmt::Debug, fs::File, path::PathBuf, process::exit, time::Duration as StdDuration};
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};
use url::Url;

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

// Parsers for command-line arguments:

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
#[clap(rename_all = "lower")]
enum VdafType {
    /// Prio3Count
    Count,
    /// Prio3CountVec
    CountVec,
    /// Prio3Sum
    Sum,
    /// Prio3SumVec
    SumVec,
    /// Prio3Histogram
    Histogram,
    #[cfg(feature = "fpvec_bounded_l2")]
    /// Prio3FixedPoint16BitBoundedL2VecSum
    FixedPoint16BitBoundedL2VecSum,
    #[cfg(feature = "fpvec_bounded_l2")]
    /// Prio3FixedPoint32BitBoundedL2VecSum
    FixedPoint32BitBoundedL2VecSum,
    #[cfg(feature = "fpvec_bounded_l2")]
    /// Prio3FixedPoint64BitBoundedL2VecSum
    FixedPoint64BitBoundedL2VecSum,
}

#[derive(Clone)]
struct TaskIdValueParser {
    inner: NonEmptyStringValueParser,
}

impl TaskIdValueParser {
    fn new() -> TaskIdValueParser {
        TaskIdValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for TaskIdValueParser {
    type Value = TaskId;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        let task_id_bytes: [u8; TaskId::LEN] = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?
            .try_into()
            .map_err(|_| {
                clap::Error::raw(ErrorKind::ValueValidation, "task ID length incorrect")
            })?;
        Ok(TaskId::from(task_id_bytes))
    }
}

#[derive(Clone)]
struct CollectionJobIdValueParser {
    inner: NonEmptyStringValueParser,
}

impl CollectionJobIdValueParser {
    fn new() -> CollectionJobIdValueParser {
        CollectionJobIdValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for CollectionJobIdValueParser {
    type Value = CollectionJobId;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        let collection_job_id = input
            .parse()
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, format!("{:?}", err)))?;
        Ok(collection_job_id)
    }
}

#[derive(Clone)]
struct BatchIdValueParser {
    inner: NonEmptyStringValueParser,
}

impl BatchIdValueParser {
    fn new() -> BatchIdValueParser {
        BatchIdValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for BatchIdValueParser {
    type Value = BatchId;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        let batch_id_bytes: [u8; BatchId::LEN] = URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?
            .try_into()
            .map_err(|_| {
                clap::Error::raw(ErrorKind::ValueValidation, "batch ID length incorrect")
            })?;
        Ok(BatchId::from(batch_id_bytes))
    }
}

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

#[derive(Debug, Args, PartialEq, Eq)]
struct AuthenticationOptions {
    /// Authentication token for the DAP-Auth-Token HTTP header
    #[clap(
        long,
        value_parser = StringValueParser::new().try_map(AuthenticationToken::new_dap_auth_token_from_string),
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
        value_parser = StringValueParser::new().try_map(AuthenticationToken::new_bearer_token_from_string),
        env,
        hide_env_values = true,
        help_heading = "Authorization",
        display_order = 1,
        conflicts_with = "dap_auth_token"
    )]
    authorization_bearer_token: Option<AuthenticationToken>,
}

#[derive(Debug, Args, PartialEq, Eq)]
#[group(required = true)]
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

    /// Batch identifier, encoded with base64url
    #[clap(
        long,
        value_parser = BatchIdValueParser::new(),
        conflicts_with_all = ["batch_interval_start", "batch_interval_duration", "current_batch"],
        help_heading = "Collect Request Parameters (Fixed Size)",
    )]
    batch_id: Option<BatchId>,
    /// Have the aggregator select a batch that has not yet been collected
    #[clap(
        long,
        action = ArgAction::SetTrue,
        conflicts_with_all = ["batch_interval_start", "batch_interval_duration", "batch_id"],
        help_heading = "Collect Request Parameters (Fixed Size)",
    )]
    current_batch: bool,
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
        #[clap(value_parser = CollectionJobIdValueParser::new())]
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
        #[clap(value_parser = CollectionJobIdValueParser::new(), required = true)]
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
    #[clap(
        long,
        value_parser = TaskIdValueParser::new(),
        help_heading = "DAP Task Parameters",
        display_order = 0
    )]
    task_id: TaskId,
    /// The leader aggregator's endpoint URL
    #[clap(long, help_heading = "DAP Task Parameters", display_order = 1)]
    leader: Url,

    #[clap(flatten)]
    authentication: AuthenticationOptions,

    #[clap(flatten)]
    hpke_config: HpkeConfigOptions,

    /// VDAF algorithm
    #[clap(
        long,
        value_enum,
        help_heading = "VDAF Algorithm and Parameters",
        display_order = 0
    )]
    vdaf: VdafType,
    /// Number of vector elements, when used with --vdaf=countvec and --vdaf=sumvec or number of
    /// histogram buckets, when used with --vdaf=histogram
    #[clap(long, help_heading = "VDAF Algorithm and Parameters")]
    length: Option<usize>,
    /// Bit length of measurements, for use with --vdaf=sum and --vdaf=sumvec
    #[clap(long, help_heading = "VDAF Algorithm and Parameters")]
    bits: Option<usize>,

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
            (None, None, Some(collector_credential)) => collector_credential.authentication_token(),
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
            (None, None, Some(collector_credential)) => Ok(collector_credential
                .hpke_keypair()
                .context("unsupported config")?),
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

macro_rules! options_query_dispatch {
    ($options:expr, ($query:ident) => $body:tt) => {
        match (
            &$options.query.batch_interval_start,
            &$options.query.batch_interval_duration,
            &$options.query.batch_id,
            $options.query.current_batch,
        ) {
            (Some(batch_interval_start), Some(batch_interval_duration), None, false) => {
                let $query = Query::new_time_interval(
                    Interval::new(
                        Time::from_seconds_since_epoch(*batch_interval_start),
                        Duration::from_seconds(*batch_interval_duration),
                    )
                    .map_err(|err| Error::Anyhow(err.into()))?,
                );
                $body
            }
            (None, None, Some(batch_id), false) => {
                let $query = Query::new_fixed_size(FixedSizeQuery::ByBatchId {
                    batch_id: *batch_id,
                });
                $body
            }
            (None, None, None, true) => {
                let $query = Query::new_fixed_size(FixedSizeQuery::CurrentBatch);
                $body
            }
            _ => unreachable!("clap argument parsing shouldn't allow this to be possible"),
        }
    };
}

macro_rules! options_vdaf_dispatch {
    ($options:expr, ($vdaf:ident) => $body:tt) => {
        match ($options.vdaf, $options.length, $options.bits) {
            (VdafType::Count, None, None) => {
                let $vdaf = Prio3::new_count(2).map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            (VdafType::CountVec, Some(length), None) => {
                // We can take advantage of the fact that Prio3SumVec unsharding does not use the
                // chunk_length parameter and avoid asking the user for it.
                let $vdaf =
                    Prio3::new_sum_vec(2, 1, length, 1).map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            (VdafType::Sum, None, Some(bits)) => {
                let $vdaf = Prio3::new_sum(2, bits).map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            (VdafType::SumVec, Some(length), Some(bits)) => {
                // We can take advantage of the fact that Prio3SumVec unsharding does not use the
                // chunk_length parameter and avoid asking the user for it.
                let $vdaf = Prio3::new_sum_vec(2, bits, length, 1)
                    .map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            (VdafType::Histogram, Some(length), None) => {
                // We can take advantage of the fact that Prio3Histogram unsharding does not use the
                // chunk_length parameter and avoid asking the user for it.
                let $vdaf =
                    Prio3::new_histogram(2, length, 1).map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            (VdafType::FixedPoint16BitBoundedL2VecSum, Some(length), None) => {
                let $vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                        .map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            #[cfg(feature = "fpvec_bounded_l2")]
            (VdafType::FixedPoint32BitBoundedL2VecSum, Some(length), None) => {
                let $vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                    Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                        .map_err(|err| Error::Anyhow(err.into()))?;
                $body
            }
            _ => Err(clap::Error::raw(
                ErrorKind::ArgumentConflict,
                format!(
                    "incorrect VDAF parameter arguments were supplied for {}",
                    $options
                        .vdaf
                        .to_possible_value()
                        .unwrap()
                        .get_help()
                        .unwrap(),
                ),
            )
            .into()),
        }
    };
}

macro_rules! options_dispatch {
    ($options:expr, ($query:ident, $vdaf:ident) => $body:tt) => {
        options_query_dispatch!($options, ($query) => {
            options_vdaf_dispatch!($options, ($vdaf) => {
                $body
            })
        })
    }
}

// This function is broken out from `main()` for the sake of testing its argument handling.
async fn run(options: Options) -> Result<(), Error> {
    let http_client = default_http_client().map_err(|err| Error::Anyhow(err.into()))?;
    options_dispatch!(options, (query, vdaf) => {
        match options.subcommand {
            Some(Subcommands::NewJob { collection_job_id }) => {
                let collection_job_id = collection_job_id.unwrap_or_else(random);
                run_new_job(options, vdaf, http_client, query, &(), collection_job_id).await
            }
            Some(Subcommands::PollJob { collection_job_id }) => {
                run_poll_job(options, vdaf, http_client, query, &(), collection_job_id).await
            }
            _ => run_collection(options, vdaf, http_client, query, &()).await,
        }
    })
}

async fn run_collection<V: vdaf::Collector, Q: QueryTypeExt>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<Q>,
    agg_param: &V::AggregationParam,
) -> Result<(), Error>
where
    V::AggregateResult: Debug,
{
    let collection = new_collector(options, vdaf, http_client)?
        .collect(query, agg_param)
        .await
        .map_err(|err| Error::Anyhow(err.into()))?;
    print_collection::<V, Q>(collection)?;
    Ok(())
}

async fn run_new_job<V: vdaf::Collector, Q: QueryTypeExt>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<Q>,
    agg_param: &V::AggregationParam,
    collection_job_id: CollectionJobId,
) -> Result<(), Error>
where
    V::AggregateResult: Debug,
{
    let collection = new_collector(options, vdaf, http_client)?
        .start_collection_with_id(collection_job_id, query, agg_param)
        .await
        .map_err(|err| Error::Anyhow(err.into()))?;
    println!("Job ID: {}", collection.collection_job_id());
    Ok(())
}

async fn run_poll_job<V: vdaf::Collector, Q: QueryTypeExt>(
    options: Options,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<Q>,
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
            print_collection::<V, Q>(collection)?;
            Ok(())
        }
        PollResult::NotReady(retry_after) => {
            println!("State: Not ready");
            match retry_after {
                Some(retry_after) => println!("Retry after: {:?}", retry_after),
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
    let task_id = options.task_id;
    let leader_endpoint = options.leader;
    let collector =
        Collector::builder(task_id, leader_endpoint, authentication, hpke_keypair, vdaf)
            .with_http_client(http_client)
            .with_collect_poll_backoff(ExponentialBackoff {
                initial_interval: StdDuration::from_secs(3),
                max_interval: StdDuration::from_secs(300),
                multiplier: 1.2,
                max_elapsed_time: None,
                randomization_factor: 0.1,
                ..Default::default()
            })
            .build()
            .map_err(|err| Error::Anyhow(err.into()))?;
    Ok(collector)
}

fn print_collection<V: vdaf::Collector, Q: QueryTypeExt>(
    collection: Collection<<V as Vdaf>::AggregateResult, Q>,
) -> Result<(), Error> {
    if !Q::IS_PARTIAL_BATCH_SELECTOR_TRIVIAL {
        println!(
            "Batch: {}",
            Q::format_partial_batch_selector(collection.partial_batch_selector())
        );
    }
    let (start, duration) = collection.interval();

    println!("Number of reports: {}", collection.report_count());
    println!("Interval start: {}", start);
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

trait QueryTypeExt: QueryType {
    const IS_PARTIAL_BATCH_SELECTOR_TRIVIAL: bool;

    fn format_partial_batch_selector(partial_batch_selector: &PartialBatchSelector<Self>)
        -> String;
}

impl QueryTypeExt for TimeInterval {
    const IS_PARTIAL_BATCH_SELECTOR_TRIVIAL: bool = true;

    fn format_partial_batch_selector(_: &PartialBatchSelector<Self>) -> String {
        "()".to_string()
    }
}

impl QueryTypeExt for FixedSize {
    const IS_PARTIAL_BATCH_SELECTOR_TRIVIAL: bool = false;

    fn format_partial_batch_selector(
        partial_batch_selector: &PartialBatchSelector<Self>,
    ) -> String {
        URL_SAFE_NO_PAD.encode(partial_batch_selector.batch_id().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        run, AuthenticationOptions, AuthenticationToken, Error, HpkeConfigOptions, Options,
        QueryOptions, Subcommands, VdafType,
    };
    use assert_matches::assert_matches;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use clap::{error::ErrorKind, CommandFactory, Parser};
    use janus_collector::PrivateCollectorCredential;
    use janus_core::{
        auth_tokens::{BearerToken, DapAuthToken},
        hpke::test_util::generate_test_hpke_config_and_private_key,
    };
    use janus_messages::{BatchId, TaskId};
    use prio::codec::Encode;
    use rand::random;
    use reqwest::Url;
    use std::io::Write;
    use tempfile::NamedTempFile;

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

    #[test]
    fn verify_app() {
        Options::command().debug_assert();
    }

    #[tokio::test]
    async fn argument_handling() {
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let task_id = random();
        let leader = Url::parse("https://example.com/dap/").unwrap();
        let auth_token = AuthenticationToken::DapAuth(random());

        let expected = Options {
            subcommand: None,
            task_id,
            leader: leader.clone(),
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
            vdaf: VdafType::Count,
            length: None,
            bits: None,
            query: QueryOptions {
                batch_interval_start: Some(1_000_000),
                batch_interval_duration: Some(1_000),
                batch_id: None,
                current_batch: false,
            },
        };
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            "--leader",
            leader.as_str(),
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf",
            "count",
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{}\narguments were {:?}", e, correct_arguments),
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
                "--leader",
                leader.as_str(),
                &format!("--dap-auth-token={}", auth_token.as_str()),
                "--vdaf",
                "count",
                "--batch-interval-start",
                "1000000",
                "--batch-interval-duration",
                "1000",
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
        bad_arguments[3] = "http:bad:url:///dap@";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments;
        bad_arguments[5] = "--hpke-config=not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments;
        bad_arguments[6] = "--hpke-private-key=not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            "--leader".to_string(),
            leader.to_string(),
            format!("--dap-auth-token={}", auth_token.as_str()),
            format!("--hpke-config={encoded_hpke_config}"),
            format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
        ]);

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=countvec".to_string(), "--bits=3".to_string()]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
        );

        #[cfg(feature = "fpvec_bounded_l2")]
        {
            let mut bad_arguments = base_arguments.clone();
            bad_arguments.extend([
                "--vdaf=fixedpoint16bitboundedl2vecsum".to_string(),
                "--bits=3".to_string(),
            ]);
            let bad_options = Options::try_parse_from(bad_arguments).unwrap();
            assert_matches!(
                run(bad_options).await.unwrap_err(),
                Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
            );

            let mut bad_arguments = base_arguments.clone();
            bad_arguments.extend([
                "--vdaf=fixedpoint32bitboundedl2vecsum".to_string(),
                "--bits=3".to_string(),
            ]);
            let bad_options = Options::try_parse_from(bad_arguments).unwrap();
            assert_matches!(
                run(bad_options).await.unwrap_err(),
                Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
            );

            let mut bad_arguments = base_arguments.clone();
            bad_arguments.extend([
                "--vdaf=fixedpoint64bitboundedl2vecsum".to_string(),
                "--bits=3".to_string(),
            ]);
            let bad_options = Options::try_parse_from(bad_arguments).unwrap();
            assert_matches!(
                run(bad_options).await.unwrap_err(),
                Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
            );
        }

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=histogram".to_string(), "--length=apple".to_string()]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=histogram".to_string()]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=sum".to_string()]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind(), ErrorKind::ArgumentConflict)
        );

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend(["--vdaf=countvec".to_string(), "--length=10".to_string()]);
        Options::try_parse_from(good_arguments).unwrap();

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend(["--vdaf=sum".to_string(), "--bits=8".to_string()]);
        Options::try_parse_from(good_arguments).unwrap();

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend([
            "--vdaf=sumvec".to_string(),
            "--bits=8".to_string(),
            "--length=10".to_string(),
        ]);
        Options::try_parse_from(good_arguments).unwrap();

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend(["--vdaf=histogram".to_string(), "--length=4".to_string()]);
        Options::try_parse_from(good_arguments).unwrap();

        #[cfg(feature = "fpvec_bounded_l2")]
        {
            let mut good_arguments = base_arguments.clone();
            good_arguments.extend([
                "--vdaf=fixedpoint16bitboundedl2vecsum".to_string(),
                "--length=10".to_string(),
            ]);
            Options::try_parse_from(good_arguments).unwrap();

            let mut good_arguments = base_arguments.clone();
            good_arguments.extend([
                "--vdaf=fixedpoint32bitboundedl2vecsum".to_string(),
                "--length=10".to_string(),
            ]);
            Options::try_parse_from(good_arguments).unwrap();

            let mut good_arguments = base_arguments.clone();
            good_arguments.extend([
                "--vdaf=fixedpoint64bitboundedl2vecsum".to_string(),
                "--length=10".to_string(),
            ]);
            Options::try_parse_from(good_arguments).unwrap();
        }
    }

    #[test]
    fn batch_arguments() {
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());

        let leader = Url::parse("https://example.com/dap/").unwrap();

        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());
        let auth_token = AuthenticationToken::DapAuth(random());

        // Check parsing arguments for a current batch query.
        let expected = Options {
            subcommand: None,
            task_id,
            leader: leader.clone(),
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
            vdaf: VdafType::Count,
            length: None,
            bits: None,
            query: QueryOptions {
                batch_interval_start: None,
                batch_interval_duration: None,
                batch_id: None,
                current_batch: true,
            },
        };
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            "--leader",
            leader.as_str(),
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf",
            "count",
            "--current-batch",
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{}\narguments were {:?}", e, correct_arguments),
        }

        // Check parsing arguments for a by-batch-id query.
        let batch_id: BatchId = random();
        let batch_id_encoded = URL_SAFE_NO_PAD.encode(batch_id.as_ref());
        let expected = Options {
            subcommand: None,
            task_id,
            leader: leader.clone(),
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
            vdaf: VdafType::Count,
            length: None,
            bits: None,
            query: QueryOptions {
                batch_interval_start: None,
                batch_interval_duration: None,
                batch_id: Some(batch_id),
                current_batch: false,
            },
        };
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            "--leader",
            leader.as_str(),
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf",
            "count",
            &format!("--batch-id={batch_id_encoded}"),
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{}\narguments were {:?}", e, correct_arguments),
        }

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            "--leader".to_string(),
            "https://example.com/dap/".to_string(),
            format!("--dap-auth-token={}", auth_token.as_str()),
            format!("--hpke-config={encoded_hpke_config}"),
            format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf=count".to_string(),
        ]);

        let mut good_arguments = base_arguments.clone();
        good_arguments.push("--current-batch".to_string());
        Options::try_parse_from(good_arguments).unwrap();

        // Check that clap enforces all the constraints we need on combinations of query arguments.
        // This allows us to treat a default match branch as `unreachable!()` when unpacking the
        // argument matches.

        assert_eq!(
            Options::try_parse_from(base_arguments.clone())
                .unwrap_err()
                .kind(),
            ErrorKind::MissingRequiredArgument
        );

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

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend([
            "--batch-interval-start=1".to_string(),
            "--batch-interval-duration=1".to_string(),
            "--batch-id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend([
            "--batch-interval-start=1".to_string(),
            "--batch-id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend([
            "--batch-interval-duration=1".to_string(),
            "--batch-id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend([
            "--batch-interval-start=1".to_string(),
            "--current-batch".to_string(),
        ]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend([
            "--batch-interval-duration=1".to_string(),
            "--current-batch".to_string(),
        ]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );

        let mut bad_arguments = base_arguments;
        bad_arguments.extend([
            "--batch-id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            "--current-batch".to_string(),
        ]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn auth_arguments() {
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());

        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            "--leader".to_string(),
            "https://example.com/dap/".to_string(),
            format!("--hpke-config={encoded_hpke_config}"),
            format!("--hpke-private-key={encoded_private_key}"),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
            "--vdaf=count".to_string(),
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
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());
        let bearer_token: BearerToken = random();
        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            "--leader".to_string(),
            "https://example.com/dap/".to_string(),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
            "--vdaf=count".to_string(),
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
                collector_credential.authentication_token().unwrap(),
                collector_credential.hpke_keypair().unwrap()
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
                collector_credential.hpke_keypair().unwrap()
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
                collector_credential.authentication_token().unwrap(),
                collector_credential.hpke_keypair().unwrap()
            ),
        );
    }

    #[test]
    fn collector_credential() {
        let collector_credential =
            serde_json::from_str::<PrivateCollectorCredential>(SAMPLE_COLLECTOR_CREDENTIAL)
                .unwrap();
        let task_id: TaskId = random();
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());
        let bearer_token: BearerToken = random();

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            "--leader".to_string(),
            "https://example.com/dap/".to_string(),
            "--batch-interval-start".to_string(),
            "1000000".to_string(),
            "--batch-interval-duration".to_string(),
            "1000".to_string(),
            "--vdaf=count".to_string(),
            format!("--authorization-bearer-token={}", bearer_token.as_str()),
            format!("--collector-credential={}", SAMPLE_COLLECTOR_CREDENTIAL),
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
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());
        let leader = Url::parse("https://example.com/dap/").unwrap();
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());
        let auth_token = AuthenticationToken::DapAuth(random());

        let base_arguments = Vec::from([
            "collect".to_string(),
            format!("--task-id={task_id_encoded}"),
            "--leader".to_string(),
            leader.to_string(),
            format!("--dap-auth-token={}", auth_token.as_str()),
            "--vdaf".to_string(),
            "count".to_string(),
            "--current-batch".to_string(),
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
            "--collector-credential={}",
            SAMPLE_COLLECTOR_CREDENTIAL
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
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let task_id = random();
        let leader = Url::parse("https://example.com/dap/").unwrap();
        let auth_token = AuthenticationToken::DapAuth(random());

        let mut expected = Options {
            subcommand: Some(Subcommands::NewJob {
                collection_job_id: None,
            }),
            task_id,
            leader: leader.clone(),
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
            vdaf: VdafType::Count,
            length: None,
            bits: None,
            query: QueryOptions {
                batch_interval_start: Some(1_000_000),
                batch_interval_duration: Some(1_000),
                batch_id: None,
                current_batch: false,
            },
        };
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            "--leader",
            leader.as_str(),
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf",
            "count",
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
            "new-job",
        ];
        match Options::try_parse_from(correct_arguments) {
            Ok(got) => assert_eq!(got, expected),
            Err(e) => panic!("{}\narguments were {:?}", e, correct_arguments),
        }

        let collection_job_id = random();
        expected.subcommand = Some(Subcommands::NewJob {
            collection_job_id: Some(collection_job_id),
        });
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            "--leader",
            leader.as_str(),
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf",
            "count",
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
            Err(e) => panic!("{}\narguments were {:?}", e, correct_arguments),
        }
    }

    #[test]
    fn subcommand_poll_job_arguments() {
        let hpke_keypair = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = URL_SAFE_NO_PAD.encode(hpke_keypair.config().get_encoded());
        let encoded_private_key = URL_SAFE_NO_PAD.encode(hpke_keypair.private_key().as_ref());

        let task_id = random();
        let leader = Url::parse("https://example.com/dap/").unwrap();
        let auth_token = AuthenticationToken::DapAuth(random());
        let collection_job_id = random();
        let expected = Options {
            subcommand: Some(Subcommands::PollJob { collection_job_id }),
            task_id,
            leader: leader.clone(),
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
            vdaf: VdafType::Count,
            length: None,
            bits: None,
            query: QueryOptions {
                batch_interval_start: Some(1_000_000),
                batch_interval_duration: Some(1_000),
                batch_id: None,
                current_batch: false,
            },
        };
        let task_id_encoded = URL_SAFE_NO_PAD.encode(task_id.get_encoded());
        let correct_arguments = [
            "collect",
            &format!("--task-id={task_id_encoded}"),
            "--leader",
            leader.as_str(),
            &format!("--dap-auth-token={}", auth_token.as_str()),
            &format!("--hpke-config={encoded_hpke_config}"),
            &format!("--hpke-private-key={encoded_private_key}"),
            "--vdaf",
            "count",
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
            Err(e) => panic!("{}\narguments were {:?}", e, correct_arguments),
        }

        let mut bad_arguments = correct_arguments;
        bad_arguments[bad_arguments.len() - 1] = "invalid";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );
    }
}
