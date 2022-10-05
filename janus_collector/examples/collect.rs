use base64::URL_SAFE_NO_PAD;
use clap::{
    builder::{NonEmptyStringValueParser, StringValueParser, TypedValueParser},
    error::ErrorKind,
    ArgAction, CommandFactory, FromArgMatches, Parser, ValueEnum,
};
use derivative::Derivative;
use janus_collector::{default_http_client, Collector, CollectorParameters};
use janus_core::{hpke::HpkePrivateKey, task::AuthenticationToken};
use janus_messages::{Duration, HpkeConfig, Interval, TaskId, Time};
use prio::{
    codec::Decode,
    vdaf::{self, prio3::Prio3},
};
use std::fmt::Debug;
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
    /// Prio3Aes128Count
    Count,
    /// Prio3Aes128CountVec
    CountVec,
    /// Prio3Aes128Sum
    Sum,
    /// Prio3Aes128Histogram
    Histogram,
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
        let task_id_bytes: [u8; TaskId::LEN] = base64::decode_config(input, URL_SAFE_NO_PAD)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?
            .try_into()
            .map_err(|_| {
                clap::Error::raw(ErrorKind::ValueValidation, "task ID length incorrect")
            })?;
        Ok(TaskId::from(task_id_bytes))
    }
}

fn parse_authentication_token(value: String) -> AuthenticationToken {
    AuthenticationToken::from(value.into_bytes())
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
        let bytes = base64::decode_config(input, URL_SAFE_NO_PAD)
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
        let bytes = base64::decode_config(input, URL_SAFE_NO_PAD)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))?;
        Ok(HpkePrivateKey::new(bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Buckets(Vec<u64>);

#[derive(Clone)]
struct BucketsValueParser {
    inner: NonEmptyStringValueParser,
}

impl BucketsValueParser {
    fn new() -> BucketsValueParser {
        BucketsValueParser {
            inner: NonEmptyStringValueParser::new(),
        }
    }
}

impl TypedValueParser for BucketsValueParser {
    type Value = Buckets;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let input = self.inner.parse_ref(cmd, arg, value)?;
        input
            .split(',')
            .map(|chunk| chunk.trim().parse())
            .collect::<Result<Vec<_>, _>>()
            .map(Buckets)
            .map_err(|err| clap::Error::raw(ErrorKind::ValueValidation, err))
    }
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
    #[clap(long, help_heading = "DAP TASK PARAMETERS", display_order = 1)]
    leader: Url,
    /// Authentication token for the DAP-Auth-Token HTTP header
    #[clap(
        long,
        value_parser = StringValueParser::new().map(parse_authentication_token),
        env,
        help_heading = "DAP Task Parameters",
        display_order = 2
    )]
    #[derivative(Debug = "ignore")]
    auth_token: AuthenticationToken,
    /// DAP message for the collector's HPKE configuration, encoded with base64url
    #[clap(
        long,
        value_parser = HpkeConfigValueParser::new(),
        help_heading = "DAP Task Parameters",
        display_order = 3
    )]
    hpke_config: HpkeConfig,
    /// The collector's HPKE private key, encoded with base64url
    #[clap(
        long,
        value_parser = PrivateKeyValueParser::new(),
        env,
        help_heading = "DAP Task Parameters",
        display_order = 4
    )]
    #[derivative(Debug = "ignore")]
    hpke_private_key: HpkePrivateKey,

    /// VDAF algorithm
    #[clap(
        long,
        value_enum,
        help_heading = "VDAF Algorithm and Parameters",
        display_order = 0
    )]
    vdaf: VdafType,
    /// Number of vector elements, for use with --vdaf=countvec
    #[clap(long, help_heading = "VDAF Algorithm and Parameters")]
    length: Option<usize>,
    /// Bit length of measurements, for use with --vdaf=sum
    #[clap(long, help_heading = "VDAF Algorithm and Parameters")]
    bits: Option<u32>,
    /// Comma-separated list of bucket boundaries, for use with --vdaf=histogram
    #[clap(
        long,
        required = false,
        num_args = 1,
        action = ArgAction::Set,
        value_parser = BucketsValueParser::new(),
        help_heading = "VDAF Algorithm and Parameters"
    )]
    buckets: Option<Buckets>,

    /// Start of the collection batch interval, as the number of seconds since the Unix epoch
    #[clap(long, help_heading = "Collect Request Parameters")]
    batch_interval_start: u64,
    /// Duration of the collection batch interval, in seconds
    #[clap(long, help_heading = "Collect Request Parameters")]
    batch_interval_duration: u64,
}

fn install_tracing_subscriber() -> anyhow::Result<()> {
    let stdout_filter = EnvFilter::from_default_env();
    let layer = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .pretty();
    let subscriber = Registry::default().with(stdout_filter.and_then(layer));
    tracing::subscriber::set_global_default(subscriber)?;

    LogTracer::init()?;

    Ok(())
}

async fn run_collection_generic<V: vdaf::Collector>(
    parameters: CollectorParameters,
    vdaf: V,
    http_client: reqwest::Client,
    interval: Interval,
    agg_param: &V::AggregationParam,
) -> Result<(), janus_collector::Error>
where
    for<'a> Vec<u8>: From<&'a V::AggregateShare>,
    V::AggregateResult: Debug,
{
    let collector = Collector::new(parameters, vdaf, http_client);
    let agg_result = collector.collect(interval, agg_param).await?;
    println!("Aggregation result: {:?}", agg_result);
    Ok(())
}

// This function is broken out from `main()` for the sake of testing its argument handling.
async fn run(options: Options) -> Result<(), Error> {
    let parameters = CollectorParameters::new(
        options.task_id,
        options.leader,
        options.auth_token,
        options.hpke_config,
        options.hpke_private_key,
    );
    let http_client = default_http_client().map_err(|err| Error::Anyhow(err.into()))?;
    let interval = Interval::new(
        Time::from_seconds_since_epoch(options.batch_interval_start),
        Duration::from_seconds(options.batch_interval_duration),
    )
    .map_err(|err| Error::Anyhow(err.into()))?;
    match (options.vdaf, options.length, options.bits, options.buckets) {
        (VdafType::Count, None, None, None) => {
            let vdaf = Prio3::new_aes128_count(2).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, interval, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::CountVec, Some(length), None, None) => {
            let vdaf =
                Prio3::new_aes128_count_vec(2, length).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, interval, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::Sum, None, Some(bits), None) => {
            let vdaf = Prio3::new_aes128_sum(2, bits).map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, interval, &())
                .await
                .map_err(|err| Error::Anyhow(err.into()))
        }
        (VdafType::Histogram, None, None, Some(ref buckets)) => {
            let vdaf = Prio3::new_aes128_histogram(2, &buckets.0)
                .map_err(|err| Error::Anyhow(err.into()))?;
            run_collection_generic(parameters, vdaf, http_client, interval, &())
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use janus_core::hpke::test_util::generate_test_hpke_config_and_private_key;
    use prio::codec::Encode;

    #[test]
    fn verify_app() {
        Options::command().debug_assert();
    }

    #[tokio::test]
    async fn argument_handling() {
        let (hpke_config, hpke_private_key) = generate_test_hpke_config_and_private_key();
        let encoded_hpke_config = base64::encode_config(hpke_config.get_encoded(), URL_SAFE_NO_PAD);
        let encoded_private_key = base64::encode_config(hpke_private_key.as_ref(), URL_SAFE_NO_PAD);

        let task_id = TaskId::random();
        let task_id_encoded = base64::encode_config(task_id.get_encoded(), URL_SAFE_NO_PAD);

        let leader = Url::parse("https://example.com/dap/").unwrap();

        let auth_token = AuthenticationToken::from(b"collector-authentication-token".to_vec());

        let expected = Options {
            task_id,
            leader: leader.clone(),
            auth_token,
            hpke_config,
            hpke_private_key,
            vdaf: VdafType::Count,
            length: None,
            bits: None,
            buckets: None,
            batch_interval_start: 1_000_000,
            batch_interval_duration: 1_000,
        };
        let correct_arguments = [
            "collect",
            "--task-id",
            &task_id_encoded,
            "--leader",
            leader.as_str(),
            "--auth-token",
            "collector-authentication-token",
            "--hpke-config",
            &encoded_hpke_config,
            "--hpke-private-key",
            &encoded_private_key,
            "--vdaf",
            "count",
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
        ];
        let got = Options::try_parse_from(correct_arguments).unwrap();
        assert_eq!(got, expected);

        assert_eq!(
            Options::try_parse_from(["collect"]).unwrap_err().kind(),
            ErrorKind::MissingRequiredArgument,
        );

        let mut bad_arguments = correct_arguments.clone();
        bad_arguments[2] = "not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments.clone();
        let short_encoded = base64::encode_config("too short", URL_SAFE_NO_PAD);
        bad_arguments[2] = &short_encoded;
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments.clone();
        bad_arguments[4] = "http:bad:url:///dap@";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments.clone();
        bad_arguments[8] = "not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let mut bad_arguments = correct_arguments.clone();
        bad_arguments[10] = "not valid base64";
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation,
        );

        let base_arguments = vec![
            "collect",
            "--task-id",
            &task_id_encoded,
            "--leader",
            leader.as_str(),
            "--auth-token",
            "collector-authentication-token",
            "--hpke-config",
            &encoded_hpke_config,
            "--hpke-private-key",
            &encoded_private_key,
            "--batch-interval-start",
            "1000000",
            "--batch-interval-duration",
            "1000",
        ];

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=count", "--buckets=1,2,3,4"]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind, ErrorKind::ArgumentConflict)
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=sum", "--buckets=1,2,3,4"]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind, ErrorKind::ArgumentConflict)
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=countvec", "--buckets=1,2,3,4"]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind, ErrorKind::ArgumentConflict)
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=countvec", "--bits=3"]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind, ErrorKind::ArgumentConflict)
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=histogram", "--buckets=1,2,3,4,apple"]);
        assert_eq!(
            Options::try_parse_from(bad_arguments).unwrap_err().kind(),
            ErrorKind::ValueValidation
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=histogram"]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind, ErrorKind::ArgumentConflict)
        );

        let mut bad_arguments = base_arguments.clone();
        bad_arguments.extend(["--vdaf=sum"]);
        let bad_options = Options::try_parse_from(bad_arguments).unwrap();
        assert_matches!(
            run(bad_options).await.unwrap_err(),
            Error::Clap(err) => assert_eq!(err.kind, ErrorKind::ArgumentConflict)
        );

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend(["--vdaf=countvec", "--length=10"]);
        Options::try_parse_from(good_arguments).unwrap();

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend(["--vdaf=sum", "--bits=8"]);
        Options::try_parse_from(good_arguments).unwrap();

        let mut good_arguments = base_arguments.clone();
        good_arguments.extend(["--vdaf=histogram", "--buckets=1,2,3,4"]);
        Options::try_parse_from(good_arguments).unwrap();
    }
}
