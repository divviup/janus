//! Functionality for tests interacting with Daphne (<https://github.com/cloudflare/daphne>).

use backoff::{retry, ExponentialBackoff};
use janus_core::message::{HpkeAeadId, HpkeConfig, HpkeKdfId, HpkeKemId, Role};
use janus_server::task::{Task, VdafInstance};
use lazy_static::lazy_static;
use nix::{
    sys::signal::{killpg, Signal},
    unistd::{getpgid, Pid},
};
use rand::{thread_rng, Rng};
use reqwest::Url;
use serde::Serialize;
use serde_json::json;
use std::{
    collections::HashMap,
    fmt::Write as _,
    fs::{self, File},
    io::Write as _,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    rc::Rc,
    sync::mpsc,
    time::Duration,
};
use subprocess::{Popen, PopenConfig, Redirection};
use tempfile::{tempdir, NamedTempFile, TempDir, TempPath};
use tokio::{select, sync::oneshot, task, time::interval};

lazy_static! {
    static ref DAPHNE_CODE_DIR: TempDir = {
        let code_dir = tempdir().unwrap();
        fs::write(
            code_dir.path().join("index.wasm"),
            include_bytes!("../artifacts/daphne_compiled/index.wasm"),
        )
        .unwrap();
        fs::write(
            code_dir.path().join("shim.mjs"),
            include_bytes!("../artifacts/daphne_compiled/shim.mjs"),
        )
        .unwrap();
        code_dir
    };
}

/// Represents a running Daphne test instance.
pub struct Daphne {
    // Dependencies.
    daphne_process: Popen,
    _wrangler_path: TempPath,
    _env_path: TempPath,

    // Task lifetime management.
    start_shutdown_sender: Option<oneshot::Sender<()>>,
    shutdown_complete_receiver: Option<mpsc::Receiver<()>>,
}

impl Daphne {
    // Create & start a new hermetic Daphne test instance listening on the given port, configured
    // to service the given task.
    pub fn new(port: u16, task: &Task) -> Self {
        // Generate values needed for the Daphne environment configuration based on the provided
        // Janus task definition.

        // Daphne currently only supports an HPKE config of (X25519HkdfSha256, HkdfSha256,
        // Aes128Gcm); this is checked in `DaphneHpkeConfig::from`.
        let dap_hpke_receiver_config_list = serde_json::to_string(
            &task
                .hpke_keys
                .values()
                .map(|(hpke_config, private_key)| DaphneHpkeReceiverConfig {
                    config: DaphneHpkeConfig::from(hpke_config.clone()),
                    secret_key: hex::encode(private_key.as_ref()),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();

        // The DAP bucket key is an internal, private key used to map client reports to internal
        // storage buckets.
        let mut dap_bucket_key = [0; 16];
        thread_rng().fill(&mut dap_bucket_key);

        // The DAP collect ID key is an internal, private key used to map collect requests to a
        // collect job ID. (It's only used when Daphne is in the Leader role, but we populate it
        // either way.)
        let mut dap_collect_id_key = [0; 16];
        thread_rng().fill(&mut dap_collect_id_key);

        let dap_task_list = serde_json::to_string(&HashMap::from([(
            hex::encode(task.id.as_bytes()),
            DaphneDapTaskConfig {
                leader_url: task.aggregator_url(Role::Leader).unwrap().clone(),
                helper_url: task.aggregator_url(Role::Helper).unwrap().clone(),
                min_batch_duration: task.min_batch_duration.as_seconds(),
                min_batch_size: task.min_batch_size,
                vdaf: daphne_vdaf_config_from_janus_vdaf(&task.vdaf),
                vdaf_verify_key: hex::encode(task.vdaf_verify_keys.first().unwrap()),
                collector_hpke_config: DaphneHpkeConfig::from(task.collector_hpke_config.clone()),
            },
        )]))
        .unwrap();

        // Daphne allows specifying different bearer tokens for aggregator-aggregator vs
        // aggregator-collector auth. We choose to use the same key for both, since Janus currently
        // only supports a single bearer token.
        //
        // Separately, Daphne currently only supports one auth token per task. Janus supports
        // multiple tokens per task to support rotation; we supply Daphne with the "primary" token.
        let bearer_token_list = json!({
            hex::encode(task.id.as_bytes()): String::from_utf8(task.agg_auth_tokens.first().unwrap().as_bytes().to_vec()).unwrap()
        }).to_string();

        // Write wrangler.toml.
        let wrangler_content = toml::to_string(&WranglerConfig {
            workers_dev: true,
            build_type: "javascript".to_string(),
            compatibility_date: "2022-01-20".to_string(),

            build: WranglerBuildConfig {
                upload: WranglerBuildUploadConfig {
                    dir: DAPHNE_CODE_DIR
                        .path()
                        .canonicalize()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                    format: "modules".to_string(),
                    main: "./shim.mjs".to_string(),

                    rules: Vec::from([WranglerBuildUploadRulesConfig {
                        globs: Vec::from(["**/*.wasm".to_string()]),
                        module_type: "CompiledWasm".to_string(),
                    }]),
                },
            },
            durable_objects: WranglerDurableObjectsConfig {
                bindings: Vec::from([
                    WranglerDurableObjectBinding {
                        name: "DAP_REPORT_STORE".to_string(),
                        class_name: "ReportStore".to_string(),
                    },
                    WranglerDurableObjectBinding {
                        name: "DAP_AGGREGATE_STORE".to_string(),
                        class_name: "AggregateStore".to_string(),
                    },
                    WranglerDurableObjectBinding {
                        name: "DAP_LEADER_AGG_JOB_QUEUE".to_string(),
                        class_name: "LeaderAggregationJobQueue".to_string(),
                    },
                    WranglerDurableObjectBinding {
                        name: "DAP_LEADER_COL_JOB_QUEUE".to_string(),
                        class_name: "LeaderCollectionJobQueue".to_string(),
                    },
                    WranglerDurableObjectBinding {
                        name: "DAP_HELPER_STATE_STORE".to_string(),
                        class_name: "HelperStateStore".to_string(),
                    },
                ]),
            },
            vars: WranglerVarsConfig {
                workers_rs_version: "0.0.10".to_string(),
            },
        })
        .unwrap();
        let mut wrangler_file = NamedTempFile::new().unwrap();
        wrangler_file.write_all(wrangler_content.as_ref()).unwrap();
        let wrangler_path = wrangler_file.into_temp_path();

        // Write environment file.
        let env_content = to_env_content(HashMap::from([
            ("DAP_ENV".to_string(), "dev".to_string()),
            (
                "DAP_AGGREGATOR_ROLE".to_string(),
                task.role.as_str().to_string(),
            ),
            (
                "DAP_HPKE_RECEIVER_CONFIG_LIST".to_string(),
                dap_hpke_receiver_config_list,
            ),
            ("DAP_BUCKET_KEY".to_string(), hex::encode(&dap_bucket_key)),
            ("DAP_BUCKET_COUNT".to_string(), "2".to_string()),
            (
                "DAP_COLLECT_ID_KEY".to_string(),
                hex::encode(&dap_collect_id_key),
            ),
            ("DAP_TASK_LIST".to_string(), dap_task_list),
            (
                "DAP_LEADER_BEARER_TOKEN_LIST".to_string(),
                bearer_token_list.clone(),
            ),
            (
                "DAP_COLLECTOR_BEARER_TOKEN_LIST".to_string(),
                bearer_token_list,
            ),
        ]));
        let mut env_file = NamedTempFile::new().unwrap();
        env_file.write_all(env_content.as_ref()).unwrap();
        let env_path = env_file.into_temp_path();

        // Start Daphne via miniflare.
        // We set the current directory as miniflare seems to require the directory specified in the
        // Wrangler config to be a subdirectory of the current working directory. We set a new
        // process group ID so that our Drop implementation can kill the process group without
        // killing the test process itself.
        let dev_null = Rc::new(
            File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap(),
        );
        let daphne_process = Popen::create(
            &[
                "miniflare",
                "--host=localhost",
                &format!("--port={}", port),
                &format!("--wrangler-config={}", wrangler_path.display()),
                &format!("--env={}", env_path.display()),
            ],
            PopenConfig {
                stdin: Redirection::RcFile(dev_null.clone()),
                stdout: Redirection::RcFile(dev_null.clone()),
                stderr: Redirection::RcFile(dev_null),
                cwd: Some(DAPHNE_CODE_DIR.path().canonicalize().unwrap().into()),
                setpgid: true,
                ..Default::default()
            },
        )
        .unwrap();

        // Wait for Daphne process to begin listening on the port.
        retry(
            // (We use ExponentialBackoff as a constant-time backoff as the built-in Constant
            // backoff will never time out.)
            ExponentialBackoff {
                initial_interval: Duration::from_millis(250),
                max_interval: Duration::from_millis(250),
                multiplier: 1.0,
                max_elapsed_time: Some(Duration::from_secs(10)),
                ..Default::default()
            },
            || {
                TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
                    .map_err(backoff::Error::transient)
            },
        )
        .unwrap();

        // Set up a task that occasionally hits the /internal/process endpoint, which is required
        // for Daphne to progress aggregations. (this is only required if Daphne is in the Leader
        // role, but for simplicity we hit the endpoint either way -- the resulting 404's do not
        // cause problems if Daphne is acting as the helper)
        let (start_shutdown_sender, mut start_shutdown_receiver) = oneshot::channel();
        let (shutdown_complete_sender, shutdown_complete_receiver) = mpsc::channel();
        task::spawn({
            let http_client = reqwest::Client::default();
            let request_url = task
                .aggregator_url(task.role)
                .unwrap()
                .join("/internal/process")
                .unwrap();
            let mut interval = interval(Duration::from_millis(250));
            async move {
                loop {
                    select! {
                        _ = interval.tick() => (),
                        _ = &mut start_shutdown_receiver => {
                            shutdown_complete_sender.send(()).unwrap();
                            return;
                        },
                    }

                    // The body is a JSON-encoding of Daphne's `InternalAggregateInfo`.
                    let _ = http_client
                        .post(request_url.clone())
                        .json(&json!({
                            "max_buckets": 2,
                            "max_reports": 1000,
                        }))
                        .send()
                        .await;
                }
            }
        });

        Self {
            daphne_process,
            _wrangler_path: wrangler_path,
            _env_path: env_path,
            start_shutdown_sender: Some(start_shutdown_sender),
            shutdown_complete_receiver: Some(shutdown_complete_receiver),
        }
    }
}

impl Drop for Daphne {
    fn drop(&mut self) {
        let start_shutdown_sender = self.start_shutdown_sender.take().unwrap();
        let shutdown_complete_receiver = self.shutdown_complete_receiver.take().unwrap();
        start_shutdown_sender.send(()).unwrap();
        shutdown_complete_receiver.recv().unwrap();

        // We signal the entire process group as miniflare creates child processes that are not
        // properly cleaned up if we signal only the main process (even if we send e.g. SIGTERM
        // instead of SIGKILL). Note that the Daphne process was exec'ed in its own process group,
        // so we aren't killing the test process.
        if let Some(daphne_pid) = self.daphne_process.pid() {
            let daphne_pgid = getpgid(Some(Pid::from_raw(daphne_pid.try_into().unwrap()))).unwrap();
            killpg(daphne_pgid, Signal::SIGKILL).unwrap();
        }
    }
}

fn daphne_vdaf_config_from_janus_vdaf(vdaf: &VdafInstance) -> daphne::VdafConfig {
    match vdaf {
        VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Count) => {
            daphne::VdafConfig::Prio3(daphne::Prio3Config::Count)
        }

        VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Histogram { buckets }) => {
            daphne::VdafConfig::Prio3(daphne::Prio3Config::Histogram {
                buckets: buckets.clone(),
            })
        }

        VdafInstance::Real(janus_core::task::VdafInstance::Prio3Aes128Sum { bits }) => {
            daphne::VdafConfig::Prio3(daphne::Prio3Config::Sum { bits: *bits })
        }

        _ => panic!("Unsupported VdafInstance: {:?}", vdaf),
    }
}

// Generates the contents of a "dotenv" file (https://www.dotenv.org) given a map from environment
// variable name to environment variable value.
fn to_env_content(env: HashMap<String, String>) -> String {
    let mut dotenv_content = String::new();
    for (env_name, env_value) in env {
        assert!(!env_value.contains('\'')); // vague attempt to avoid quoting issues
        writeln!(dotenv_content, "{} = '{}'", env_name, env_value).unwrap();
    }
    dotenv_content
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct WranglerConfig {
    workers_dev: bool,
    #[serde(rename = "type")]
    build_type: String,
    compatibility_date: String,

    build: WranglerBuildConfig,
    durable_objects: WranglerDurableObjectsConfig,
    vars: WranglerVarsConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct WranglerBuildConfig {
    upload: WranglerBuildUploadConfig,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct WranglerBuildUploadConfig {
    dir: String,
    format: String,
    main: String,

    rules: Vec<WranglerBuildUploadRulesConfig>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct WranglerBuildUploadRulesConfig {
    globs: Vec<String>,
    #[serde(rename = "type")]
    module_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct WranglerDurableObjectsConfig {
    bindings: Vec<WranglerDurableObjectBinding>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct WranglerDurableObjectBinding {
    name: String,
    class_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct WranglerVarsConfig {
    workers_rs_version: String,
}

// Corresponds to Daphne's `HpkeReceiverConfig`. We can't use that type directly as some of the
// fields we need to populate (e.g. `secret_key`) are not public.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DaphneHpkeReceiverConfig {
    config: DaphneHpkeConfig,
    secret_key: String,
}

// Corresponds to Daphne's `HpkeConfig`. We can't use that type directly as some of the fields we
// need to populate (e.g. `public_key`) are not public.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DaphneHpkeConfig {
    id: u8,
    kem_id: HpkeKemId,
    kdf_id: HpkeKdfId,
    aead_id: HpkeAeadId,
    public_key: String,
}

impl From<HpkeConfig> for DaphneHpkeConfig {
    fn from(hpke_config: HpkeConfig) -> Self {
        // Daphne currently only supports this specific HPKE configuration, so make sure that we
        // are converting something Daphne can use.
        assert_eq!(hpke_config.kem_id(), HpkeKemId::X25519HkdfSha256);
        assert_eq!(hpke_config.kdf_id(), HpkeKdfId::HkdfSha256);
        assert_eq!(hpke_config.aead_id(), HpkeAeadId::Aes128Gcm);

        DaphneHpkeConfig {
            id: u8::from(hpke_config.id()),
            kem_id: hpke_config.kem_id(),
            kdf_id: hpke_config.kdf_id(),
            aead_id: hpke_config.aead_id(),
            public_key: hex::encode(hpke_config.public_key().as_bytes()),
        }
    }
}

// Corresponds to Daphne's `DapTaskConfig`. We can't use that type directly as some of the fields we
// need to populate (e.g. `vdaf_verify_key`) are not public.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DaphneDapTaskConfig {
    pub leader_url: Url,
    pub helper_url: Url,
    pub min_batch_duration: u64,
    pub min_batch_size: u64,
    pub vdaf: daphne::VdafConfig,
    pub vdaf_verify_key: String,
    pub collector_hpke_config: DaphneHpkeConfig,
}
