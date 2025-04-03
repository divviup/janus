use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use educe::Educe;
use janus_aggregator_core::task::{test_util::Task, BatchMode};
#[cfg(feature = "fpvec_bounded_l2")]
use janus_core::vdaf::Prio3FixedPointBoundedL2VecSumBitSize;
use janus_core::{
    hpke::HpkeKeypair,
    vdaf::{vdaf_dp_strategies, VdafInstance},
};
use janus_messages::{
    batch_mode::{BatchMode as _, LeaderSelected, TimeInterval},
    HpkeAeadId, HpkeConfigId, HpkeKdfId, HpkeKemId, Role, TaskId, Time,
};
use prio::codec::Encode;
use rand::random;
use serde::{de::Visitor, Deserialize, Serialize};
use std::{
    collections::HashMap,
    env::{self, VarError},
    fmt::Display,
    fs::{create_dir_all, File},
    io::{stderr, Write},
    marker::PhantomData,
    ops::Deref,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::Arc,
};
use testcontainers::{ContainerAsync, Image};
use tokio::sync::Mutex;
use tracing_log::LogTracer;
use tracing_subscriber::{prelude::*, EnvFilter, Registry};
use trillium::{async_trait, Conn, Handler, Status};
use trillium_api::ApiConnExt;
use url::Url;

pub mod commands;

#[cfg(feature = "testcontainer")]
pub mod testcontainer;

pub mod status {
    pub static SUCCESS: &str = "success";
    pub static ERROR: &str = "error";
    pub static COMPLETE: &str = "complete";
    pub static IN_PROGRESS: &str = "in progress";
}

/// Helper type to serialize/deserialize a large number as a string.
#[derive(Debug, Clone)]
pub struct NumberAsString<T>(pub T);

impl<T> Serialize for NumberAsString<T>
where
    T: Display,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de, T> Deserialize<'de> for NumberAsString<T>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    fn deserialize<D>(deserializer: D) -> Result<NumberAsString<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(NumberAsStringVisitor::new())
    }
}

struct NumberAsStringVisitor<T>(PhantomData<T>);

impl<T> NumberAsStringVisitor<T> {
    fn new() -> NumberAsStringVisitor<T> {
        NumberAsStringVisitor(PhantomData)
    }
}

impl<T> Visitor<'_> for NumberAsStringVisitor<T>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    type Value = NumberAsString<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a string with a number in base 10")
    }

    fn visit_str<E>(self, value: &str) -> Result<NumberAsString<T>, E>
    where
        E: serde::de::Error,
    {
        let number = value
            .parse()
            .map_err(|err| E::custom(format!("string could not be parsed into number: {err}")))?;
        Ok(NumberAsString(number))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VdafObject {
    Prio3Count,
    Prio3Sum {
        max_measurement: NumberAsString<u64>,
    },
    Prio3SumVec {
        bits: NumberAsString<usize>,
        length: NumberAsString<usize>,
        chunk_length: NumberAsString<usize>,
    },
    Prio3SumVecField64MultiproofHmacSha256Aes128 {
        proofs: NumberAsString<u8>,
        bits: NumberAsString<usize>,
        length: NumberAsString<usize>,
        chunk_length: NumberAsString<usize>,
    },
    Prio3Histogram {
        length: NumberAsString<usize>,
        chunk_length: NumberAsString<usize>,
    },
    #[cfg(feature = "fpvec_bounded_l2")]
    Prio3FixedPointBoundedL2VecSum {
        bitsize: Prio3FixedPointBoundedL2VecSumBitSize,
        #[serde(default)]
        dp_strategy: vdaf_dp_strategies::Prio3FixedPointBoundedL2VecSum,
        length: NumberAsString<usize>,
    },
}

impl From<VdafInstance> for VdafObject {
    fn from(vdaf: VdafInstance) -> Self {
        match vdaf {
            VdafInstance::Prio3Count => VdafObject::Prio3Count,

            VdafInstance::Prio3Sum { max_measurement } => VdafObject::Prio3Sum {
                max_measurement: NumberAsString(max_measurement),
            },

            VdafInstance::Prio3SumVec {
                bits,
                length,
                chunk_length,
                dp_strategy: _,
            } => VdafObject::Prio3SumVec {
                bits: NumberAsString(bits),
                length: NumberAsString(length),
                chunk_length: NumberAsString(chunk_length),
            },

            VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs,
                bits,
                length,
                chunk_length,
                dp_strategy: _,
            } => VdafObject::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs: NumberAsString(proofs),
                bits: NumberAsString(bits),
                length: NumberAsString(length),
                chunk_length: NumberAsString(chunk_length),
            },

            VdafInstance::Prio3Histogram {
                length,
                chunk_length,
                dp_strategy: _,
            } => VdafObject::Prio3Histogram {
                length: NumberAsString(length),
                chunk_length: NumberAsString(chunk_length),
            },

            #[cfg(feature = "fpvec_bounded_l2")]
            VdafInstance::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy,
                length,
            } => VdafObject::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy,
                length: NumberAsString(length),
            },

            _ => panic!("Unsupported VDAF: {vdaf:?}"),
        }
    }
}

impl From<VdafObject> for VdafInstance {
    fn from(vdaf: VdafObject) -> Self {
        match vdaf {
            VdafObject::Prio3Count => VdafInstance::Prio3Count,

            VdafObject::Prio3Sum { max_measurement } => VdafInstance::Prio3Sum {
                max_measurement: max_measurement.0,
            },

            VdafObject::Prio3SumVec {
                bits,
                length,
                chunk_length,
            } => VdafInstance::Prio3SumVec {
                bits: bits.0,
                length: length.0,
                chunk_length: chunk_length.0,
                dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
            },

            VdafObject::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs,
                bits,
                length,
                chunk_length,
            } => VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
                proofs: proofs.0,
                bits: bits.0,
                length: length.0,
                chunk_length: chunk_length.0,
                dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
            },

            VdafObject::Prio3Histogram {
                length,
                chunk_length,
            } => VdafInstance::Prio3Histogram {
                length: length.0,
                chunk_length: chunk_length.0,
                dp_strategy: vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy,
            },

            #[cfg(feature = "fpvec_bounded_l2")]
            VdafObject::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy,
                length,
            } => VdafInstance::Prio3FixedPointBoundedL2VecSum {
                bitsize,
                dp_strategy,
                length: length.0,
            },
        }
    }
}

#[derive(Debug)]
pub struct BadRoleError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggregatorRole {
    Leader,
    Helper,
}

impl TryFrom<Role> for AggregatorRole {
    type Error = BadRoleError;

    fn try_from(role: Role) -> Result<Self, Self::Error> {
        match role {
            Role::Collector => Err(BadRoleError),
            Role::Client => Err(BadRoleError),
            Role::Leader => Ok(AggregatorRole::Leader),
            Role::Helper => Ok(AggregatorRole::Helper),
        }
    }
}

impl From<AggregatorRole> for Role {
    fn from(role: AggregatorRole) -> Self {
        match role {
            AggregatorRole::Leader => Role::Leader,
            AggregatorRole::Helper => Role::Helper,
        }
    }
}

#[derive(Educe, Serialize, Deserialize)]
#[educe(Debug)]
pub struct AggregatorAddTaskRequest {
    pub task_id: TaskId, // uses unpadded base64url
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    pub leader: Url,
    #[educe(Debug(method(std::fmt::Display::fmt)))]
    pub helper: Url,
    pub vdaf: VdafObject,
    pub leader_authentication_token: String,
    #[serde(default)]
    pub collector_authentication_token: Option<String>,
    pub role: AggregatorRole,
    pub vdaf_verify_key: String, // in unpadded base64url
    pub batch_mode: u8,
    pub min_batch_size: u64,
    pub time_precision: u64,           // in seconds
    pub collector_hpke_config: String, // in unpadded base64url
    pub task_start: Option<u64>,       // in seconds since the epoch
    pub task_end: Option<u64>,         // in seconds since the epoch
}

impl AggregatorAddTaskRequest {
    pub fn from_task(task: Task, role: Role) -> Self {
        let batch_mode = match task.batch_mode() {
            BatchMode::TimeInterval => TimeInterval::CODE as u8,
            BatchMode::LeaderSelected { .. } => LeaderSelected::CODE as u8,
        };
        Self {
            task_id: *task.id(),
            leader: task.leader_aggregator_endpoint().clone(),
            helper: task.helper_aggregator_endpoint().clone(),
            vdaf: task.vdaf().clone().into(),
            leader_authentication_token: String::from_utf8(
                task.aggregator_auth_token().as_ref().to_vec(),
            )
            .unwrap(),
            collector_authentication_token: if role == Role::Leader {
                Some(String::from_utf8(task.collector_auth_token().as_ref().to_vec()).unwrap())
            } else {
                None
            },
            role: role.try_into().unwrap(),
            vdaf_verify_key: URL_SAFE_NO_PAD.encode(task.opaque_vdaf_verify_key().as_ref()),
            batch_mode,
            min_batch_size: task.min_batch_size(),
            time_precision: task.time_precision().as_seconds(),
            collector_hpke_config: URL_SAFE_NO_PAD.encode(
                task.collector_hpke_keypair()
                    .config()
                    .get_encoded()
                    .unwrap(),
            ),
            task_start: task.task_start().map(Time::as_seconds_since_epoch),
            task_end: task.task_end().map(Time::as_seconds_since_epoch),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddTaskResponse {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

pub fn install_tracing_subscriber() -> anyhow::Result<()> {
    let stdout_filter = EnvFilter::builder().from_env()?;
    let layer = tracing_subscriber::fmt::layer()
        .with_thread_ids(true)
        .with_level(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .pretty();
    let subscriber = Registry::default().with(stdout_filter.and_then(layer));
    tracing::subscriber::set_global_default(subscriber)?;

    LogTracer::init()?;

    Ok(())
}

/// This registry lazily generates up to 256 HPKE key pairs, one with each possible
/// [`HpkeConfigId`].
#[derive(Default)]
pub struct HpkeConfigRegistry {
    keypairs: HashMap<HpkeConfigId, HpkeKeypair>,
}

impl HpkeConfigRegistry {
    pub fn new() -> HpkeConfigRegistry {
        Default::default()
    }

    /// Get the keypair associated with a given ID.
    pub fn fetch_keypair(&mut self, id: HpkeConfigId) -> HpkeKeypair {
        self.keypairs
            .entry(id)
            .or_insert_with(|| {
                // Unwrap safety: we always use a supported KEM.
                HpkeKeypair::generate(
                    id,
                    // These algorithms should be broadly compatible with other DAP implementations, since they
                    // are required by section 6 of draft-ietf-ppm-dap-02.
                    HpkeKemId::X25519HkdfSha256,
                    HpkeKdfId::HkdfSha256,
                    HpkeAeadId::Aes128Gcm,
                )
                .unwrap()
            })
            .clone()
    }

    /// Choose a random [`HpkeConfigId`], and then get the keypair associated with that ID.
    pub fn get_random_keypair(&mut self) -> HpkeKeypair {
        self.fetch_keypair(random::<u8>().into())
    }
}

/// log_export_path returns the path to export container logs to, or None if container logs are not
/// configured to be exported.
///
/// The resulting value is based directly on the JANUS_E2E_LOGS_PATH environment variable.
pub fn log_export_path() -> Option<PathBuf> {
    match env::var("JANUS_E2E_LOGS_PATH") {
        Ok(logs_path) => Some(PathBuf::from_str(&logs_path).unwrap()),
        Err(VarError::NotPresent) => None,
        Err(err) => panic!("Failed to parse JANUS_E2E_LOGS_PATH: {err}"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerInspectEntry {
    name: String,
}

pub struct ContainerLogsDropGuard<I: Image> {
    test_name: String,
    container: ContainerAsync<I>,
    source: ContainerLogsSource,
}

pub enum ContainerLogsSource {
    /// Logs can be gathered through the `docker logs` command.
    Docker,
    /// Logs are present inside the container at the given path.
    Path(String),
}

impl<I: Image> ContainerLogsDropGuard<I> {
    pub fn new(
        test_name: &str,
        container: ContainerAsync<I>,
        source: ContainerLogsSource,
    ) -> ContainerLogsDropGuard<I> {
        ContainerLogsDropGuard {
            test_name: test_name.into(),
            container,
            source,
        }
    }

    pub fn new_janus(test_name: &str, container: ContainerAsync<I>) -> ContainerLogsDropGuard<I> {
        ContainerLogsDropGuard {
            test_name: test_name.into(),
            container,
            source: ContainerLogsSource::Path("/logs".to_string()),
        }
    }
}

impl<I: Image> Drop for ContainerLogsDropGuard<I> {
    fn drop(&mut self) {
        // The unwraps in this code block would induce a double panic, but we accept this risk
        // since it happens only in test code. This is also our main method of debugging
        // integration tests, so if it's broken we should be alerted and have it fixed ASAP.
        if let Some(base_dir) = log_export_path() {
            let base_dir = base_dir.join(&self.test_name);
            create_dir_all(&base_dir).expect("could not create log output directory");

            let id = self.container.id();

            let inspect_output = Command::new("docker")
                .args(["container", "inspect", id])
                .output()
                .expect("running `docker container inspect` failed");
            stderr().write_all(&inspect_output.stderr).unwrap();
            assert!(inspect_output.status.success());
            let inspect_array: Vec<ContainerInspectEntry> =
                serde_json::from_slice(&inspect_output.stdout).unwrap();
            let inspect_entry = inspect_array
                .first()
                .expect("`docker container inspect` returned no results");
            let name = &inspect_entry.name[inspect_entry
                .name
                .find('/')
                .map(|index| index + 1)
                .unwrap_or_default()..];

            let destination = base_dir.join(name);

            let command_status = match self.source {
                ContainerLogsSource::Docker => {
                    create_dir_all(&destination).unwrap();
                    Command::new("docker")
                        .args(["logs", "--timestamps", id])
                        .stdin(Stdio::null())
                        .stdout(File::create(destination.join("stdout.log")).unwrap())
                        .stderr(File::create(destination.join("stderr.log")).unwrap())
                        .status()
                        .expect("running `docker logs` failed")
                }
                ContainerLogsSource::Path(ref path) => Command::new("docker")
                    .arg("cp")
                    .arg(format!("{id}:{path}"))
                    .arg(destination)
                    .status()
                    .expect("running `docker cp` failed"),
            };
            assert!(
                command_status.success(),
                "log extraction failed {command_status:?}"
            );
        }
    }
}

impl<I: Image> Deref for ContainerLogsDropGuard<I> {
    type Target = ContainerAsync<I>;

    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

pub struct ErrorHandler;

#[async_trait]
impl Handler for ErrorHandler {
    async fn run(&self, conn: Conn) -> Conn {
        conn
    }

    async fn before_send(&self, mut conn: Conn) -> Conn {
        if let Some(error) = conn.take_state::<trillium_api::Error>() {
            // Could not parse the request, return a 400 status code.
            return conn
                .with_json(&serde_json::json!({
                    "status": status::ERROR,
                    "error": format!("{error}"),
                }))
                .with_status(Status::BadRequest);
        }
        conn
    }
}

/// A wrapper around [`HpkeConfigRegistry`] that is suitable for use in Trillium connection
/// state.
#[derive(Clone)]
pub struct Keyring(pub Arc<Mutex<HpkeConfigRegistry>>);

impl Keyring {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HpkeConfigRegistry::new())))
    }
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the environment variable RUST_LOG. If it's unset or otherwise invalid, return the
/// default value of "info".
pub fn get_rust_log_level() -> String {
    env::var("RUST_LOG").unwrap_or("info".to_string())
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use backon::{BackoffBuilder, ConstantBuilder, Retryable};
    use rand::random;
    use std::time::Duration;
    use url::Url;

    /// Waits a while for the given IPv4 port to start responding successfully to
    /// "/internal/test/ready" HTTP requests, panicking if this doesn't happen soon enough.
    pub async fn await_ready_ok(port: u16) {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        // Explicitly connect to IPv4 localhost so that we don't accidentally try to talk to a
        // different container's IPv6 port.
        let url = Url::parse(&format!("http://127.0.0.1:{port}/internal/test/ready")).unwrap();

        let backoff = ConstantBuilder::new()
            .with_delay(Duration::from_millis(250))
            .with_max_times(30 * 4);

        let _ = (|| async {
            (|| async { http_client.post(url.clone()).send().await })
                .retry(backoff.build())
                .await
                .unwrap()
                .error_for_status()
        })
        .retry(backoff.build())
        .await;
    }

    /// Waits a while for the given port to start responding to HTTP requests, panicking if this
    /// doesn't happen soon enough.
    pub async fn await_http_server(port: u16) {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();

        let backoff = ConstantBuilder::new()
            .with_delay(Duration::from_millis(250))
            .with_max_times(30 * 4);

        let _ = (|| async { http_client.get(url.clone()).send().await })
            .retry(backoff.build())
            .await;
    }

    pub fn generate_network_name() -> String {
        generate_unique_name("janus_ephemeral_network")
    }

    pub fn generate_unique_name(prefix: &str) -> String {
        format!("{}-{}", prefix, hex::encode(random::<[u8; 4]>()))
    }
}
