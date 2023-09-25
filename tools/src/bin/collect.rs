use anyhow::Context;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{
    builder::{NonEmptyStringValueParser, StringValueParser, TypedValueParser},
    error::ErrorKind,
    ArgAction, Args, CommandFactory, FromArgMatches, Parser, ValueEnum,
};
use derivative::Derivative;
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::types::extra::{U15, U31, U63};
#[cfg(feature = "fpvec_bounded_l2")]
use fixed::{FixedI16, FixedI32, FixedI64};
use janus_collector::{default_http_client, AuthenticationToken, Collector, CollectorParameters};
use janus_core::hpke::{DivviUpHpkeConfig, HpkeKeypair, HpkePrivateKey};
use janus_messages::{
    query_type::{FixedSize, QueryType, TimeInterval},
    BatchId, Duration, FixedSizeQuery, HpkeConfig, Interval, PartialBatchSelector, Query, TaskId,
    Time,
};
#[cfg(feature = "fpvec_bounded_l2")]
use prio::vdaf::prio3::Prio3FixedPointBoundedL2VecSumMultithreaded;
use prio::{
    codec::Decode,
    vdaf::{self, prio3::Prio3},
};
use std::{fmt::Debug, fs::File, path::PathBuf};
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

#[derive(Derivative, Args, PartialEq, Eq)]
#[derivative(Debug)]
#[group(required = true)]
struct AuthenticationOptions {
    /// Authentication token for the DAP-Auth-Token HTTP header
    #[clap(
        long,
        required = false,
        value_parser = StringValueParser::new().try_map(AuthenticationToken::new_dap_auth_token_from_string),
        env,
        help_heading = "Authorization",
        display_order = 0,
        conflicts_with = "authorization_bearer_token"
    )]
    #[derivative(Debug = "ignore")]
    dap_auth_token: Option<AuthenticationToken>,

    /// Authentication token for the "Authorization: Bearer ..." HTTP header
    #[clap(
        long,
        required = false,
        value_parser = StringValueParser::new().try_map(AuthenticationToken::new_bearer_token_from_string),
        env,
        help_heading = "Authorization",
        display_order = 1,
        conflicts_with = "dap_auth_token"
    )]
    #[derivative(Debug = "ignore")]
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

#[derive(Derivative, Parser, PartialEq, Eq)]
#[derivative(Debug)]
#[clap(
    name = "collect",
    version,
    about = "Command-line DAP-PPM collector from ISRG's Divvi Up",
    long_about = None,
)]
struct Options {
    /// DAP task identifier, encoded with base64url
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
    /// DAP message for the collector's HPKE configuration, encoded with base64url
    #[clap(
        long,
        value_parser = HpkeConfigValueParser::new(),
        help_heading = "DAP Task Parameters",
        display_order = 2,
        requires = "hpke_private_key",
        conflicts_with = "hpke_config_json",
    )]
    hpke_config: Option<HpkeConfig>,
    /// The collector's HPKE private key, encoded with base64url
    #[clap(
        long,
        value_parser = PrivateKeyValueParser::new(),
        env,
        help_heading = "DAP Task Parameters",
        display_order = 3,
        requires = "hpke_config",
        conflicts_with = "hpke_config_json",
    )]
    #[derivative(Debug = "ignore")]
    hpke_private_key: Option<HpkePrivateKey>,
    /// Path to a JSON document containing the collector's HPKE configuration and private key, in
    /// the format output by `divviup hpke-config generate`.
    #[clap(
        long,
        help_heading = "DAP Task Parameters",
        display_order = 4,
        conflicts_with_all = ["hpke_config", "hpke_private_key"]
    )]
    hpke_config_json: Option<PathBuf>,

    #[clap(flatten)]
    authentication: AuthenticationOptions,

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
    fn hpke_keypair(&self) -> Result<HpkeKeypair, anyhow::Error> {
        match (
            &self.hpke_config,
            &self.hpke_private_key,
            &self.hpke_config_json,
        ) {
            (Some(config), Some(private), _) => {
                Ok(HpkeKeypair::new(config.clone(), private.clone()))
            }
            (None, None, Some(hpke_config_json_path)) => {
                let reader =
                    File::open(hpke_config_json_path).context("could not open HPKE config file")?;
                let divviup_hpke_config: DivviUpHpkeConfig =
                    serde_json::from_reader(reader).context("could not parse HPKE config file")?;
                HpkeKeypair::try_from(divviup_hpke_config).context("could not convert HPKE config")
            }
            _ => unreachable!(),
        }
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
    }
}

// This function is broken out from `main()` for the sake of testing its argument handling.
async fn run(options: Options) -> Result<(), Error> {
    match (
        &options.query.batch_interval_start,
        &options.query.batch_interval_duration,
        &options.query.batch_id,
        options.query.current_batch,
    ) {
        (Some(batch_interval_start), Some(batch_interval_duration), None, false) => {
            let batch_interval = Interval::new(
                Time::from_seconds_since_epoch(*batch_interval_start),
                Duration::from_seconds(*batch_interval_duration),
            )
            .map_err(|err| Error::Anyhow(err.into()))?;
            run_with_query(options, Query::new_time_interval(batch_interval)).await
        }
        (None, None, Some(batch_id), false) => {
            let batch_id = *batch_id;
            run_with_query(
                options,
                Query::new_fixed_size(FixedSizeQuery::ByBatchId { batch_id }),
            )
            .await
        }
        (None, None, None, true) => {
            run_with_query(options, Query::new_fixed_size(FixedSizeQuery::CurrentBatch)).await
        }
        _ => unreachable!(),
    }
}

async fn run_with_query<Q: QueryType>(options: Options, query: Query<Q>) -> Result<(), Error>
where
    Q: QueryTypeExt,
{
    let authentication = match (
        &options.authentication.dap_auth_token,
        &options.authentication.authorization_bearer_token,
    ) {
        (None, Some(token)) => token,
        (Some(token), None) => token,
        (None, None) | (Some(_), Some(_)) => unreachable!(),
    };

    let hpke_keypair = options.hpke_keypair()?;

    let parameters = CollectorParameters::new(
        options.task_id,
        options.leader,
        authentication.clone(),
        hpke_keypair.config().clone(),
        hpke_keypair.private_key().clone(),
    );
    let http_client = default_http_client().map_err(|err| Error::Anyhow(err.into()))?;
    match (options.vdaf, options.length, options.bits) {
        (VdafType::Count, None, None) => {
            let vdaf = Prio3::new_count(2).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::CountVec, Some(length), None) => {
            // We can take advantage of the fact that Prio3SumVec unsharding does not use the
            // chunk_length parameter and avoid asking the user for it.
            let vdaf =
                Prio3::new_sum_vec(2, 1, length, 1).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::Sum, None, Some(bits)) => {
            let vdaf = Prio3::new_sum(2, bits).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::SumVec, Some(length), Some(bits)) => {
            // We can take advantage of the fact that Prio3SumVec unsharding does not use the
            // chunk_length parameter and avoid asking the user for it.
            let vdaf =
                Prio3::new_sum_vec(2, bits, length, 1).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::Histogram, Some(length), None) => {
            // We can take advantage of the fact that Prio3Histogram unsharding does not use the
            // chunk_length parameter and avoid asking the user for it.
            let vdaf =
                Prio3::new_histogram(2, length, 1).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        #[cfg(feature = "fpvec_bounded_l2")]
        (VdafType::FixedPoint16BitBoundedL2VecSum, Some(length), None) => {
            let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI16<U15>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        #[cfg(feature = "fpvec_bounded_l2")]
        (VdafType::FixedPoint32BitBoundedL2VecSum, Some(length), None) => {
            let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI32<U31>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        #[cfg(feature = "fpvec_bounded_l2")]
        (VdafType::FixedPoint64BitBoundedL2VecSum, Some(length), None) => {
            let vdaf: Prio3FixedPointBoundedL2VecSumMultithreaded<FixedI64<U63>> =
                Prio3::new_fixedpoint_boundedl2_vec_sum_multithreaded(2, length)
                    .map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, query, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        _ => Err(clap::Error::raw(
            ErrorKind::ArgumentConflict,
            format!(
                "incorrect VDAF parameter arguments were supplied for {}",
                options
                    .vdaf
                    .to_possible_value()
                    .unwrap()
                    .get_help()
                    .unwrap(),
            ),
        )
        .into()),
    }
}

async fn run_collection_generic<V: vdaf::Collector, Q: QueryTypeExt>(
    parameters: CollectorParameters,
    vdaf: V,
    http_client: reqwest::Client,
    query: Query<Q>,
    agg_param: &V::AggregationParam,
) -> Result<(), janus_collector::Error>
where
    V::AggregateResult: Debug,
{
    let collector = Collector::new(parameters, vdaf, http_client);
    let collection = collector.collect(query, agg_param).await?;
    if !Q::IS_PARTIAL_BATCH_SELECTOR_TRIVIAL {
        println!(
            "Batch: {}",
            Q::format_partial_batch_selector(collection.partial_batch_selector())
        );
    }
    println!("Number of reports: {}", collection.report_count());
    println!(
        "Spanned interval: start: {} length: {}",
        collection.interval().0,
        collection.interval().1
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
        run, AuthenticationOptions, AuthenticationToken, Error, Options, QueryOptions, VdafType,
    };
    use assert_matches::assert_matches;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use clap::{error::ErrorKind, CommandFactory, Parser};
    use janus_core::{
        hpke::{
            test_util::{generate_test_hpke_config_and_private_key, SAMPLE_DIVVIUP_HPKE_CONFIG},
            DivviUpHpkeConfig, HpkeKeypair,
        },
        task::{BearerToken, DapAuthToken},
    };
    use janus_messages::{BatchId, TaskId};
    use prio::codec::Encode;
    use rand::random;
    use reqwest::Url;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
            task_id,
            leader: leader.clone(),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: Some(hpke_keypair.config().clone()),
            hpke_private_key: Some(hpke_keypair.private_key().clone()),
            hpke_config_json: None,
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
            task_id,
            leader: leader.clone(),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: Some(hpke_keypair.config().clone()),
            hpke_private_key: Some(hpke_keypair.private_key().clone()),
            hpke_config_json: None,
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
            task_id,
            leader: leader.clone(),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(auth_token.clone()),
                authorization_bearer_token: None,
            },
            hpke_config: Some(hpke_keypair.config().clone()),
            hpke_private_key: Some(hpke_keypair.private_key().clone()),
            hpke_config_json: None,
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
        assert_eq!(
            Options::try_parse_from(case_1_arguments)
                .unwrap()
                .authentication,
            AuthenticationOptions {
                dap_auth_token: Some(AuthenticationToken::DapAuth(dap_auth_token)),
                authorization_bearer_token: None,
            }
        );

        let mut case_2_arguments = base_arguments.clone();
        case_2_arguments.push(authorization_bearer_token_argument.clone());
        assert_eq!(
            Options::try_parse_from(case_2_arguments)
                .unwrap()
                .authentication,
            AuthenticationOptions {
                dap_auth_token: None,
                authorization_bearer_token: Some(AuthenticationToken::Bearer(bearer_token)),
            }
        );

        let case_3_arguments = base_arguments.clone();
        assert_eq!(
            Options::try_parse_from(case_3_arguments)
                .unwrap_err()
                .kind(),
            ErrorKind::MissingRequiredArgument
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
    fn hpke_config_json_file() {
        let hpke_keypair = HpkeKeypair::try_from(
            serde_json::from_str::<DivviUpHpkeConfig>(SAMPLE_DIVVIUP_HPKE_CONFIG).unwrap(),
        )
        .unwrap();

        let mut hpke_config_file = NamedTempFile::new().unwrap();
        hpke_config_file
            .write_all(SAMPLE_DIVVIUP_HPKE_CONFIG.as_bytes())
            .unwrap();
        let hpke_config_file_path = hpke_config_file.into_temp_path();

        let options = Options {
            task_id: random(),
            leader: Url::parse("https://example.com").unwrap(),
            authentication: AuthenticationOptions {
                dap_auth_token: Some(random()),
                authorization_bearer_token: None,
            },
            hpke_config: None,
            hpke_private_key: None,
            hpke_config_json: Some(hpke_config_file_path.to_path_buf()),
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

        assert_eq!(options.hpke_keypair().unwrap(), hpke_keypair);
    }
}
