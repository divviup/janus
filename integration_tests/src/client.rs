use anyhow::anyhow;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_aggregator::task::Task;
use janus_client::{aggregator_hpke_config, default_http_client, Client, ClientParameters};
use janus_core::{task::VdafInstance, time::RealClock};
use janus_interop_binaries::ContainerLogsDropGuard;
use janus_messages::{Duration, Role, TaskId};
use prio::{
    codec::Encode,
    vdaf::{
        self,
        prio3::{Prio3Aes128Count, Prio3Aes128CountVec, Prio3Aes128Histogram, Prio3Aes128Sum},
    },
};
use rand::random;
use serde_json::{json, Value};
use std::env;
use testcontainers::{clients::Cli, core::WaitFor, Image, RunnableImage};
use url::Url;

/// Extension trait to encode measurements for VDAFs as JSON objects, according to
/// draft-dcook-ppm-dap-interop-test-design.
pub trait InteropClientEncoding: vdaf::Client
where
    for<'a> Vec<u8>: From<&'a Self::AggregateShare>,
{
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value;
}

impl InteropClientEncoding for Prio3Aes128Count {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::String(format!("{measurement}"))
    }
}

impl InteropClientEncoding for Prio3Aes128Sum {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::String(format!("{measurement}"))
    }
}

impl InteropClientEncoding for Prio3Aes128Histogram {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::String(format!("{measurement}"))
    }
}

impl InteropClientEncoding for Prio3Aes128CountVec {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::Array(
            measurement
                .iter()
                .map(|value| Value::String(format!("{value}")))
                .collect(),
        )
    }
}

fn json_encode_vdaf(vdaf: &VdafInstance) -> Value {
    match vdaf {
        VdafInstance::Prio3Aes128Count => json!({
            "type": "Prio3Aes128Count"
        }),
        VdafInstance::Prio3Aes128CountVec { length } => json!({
            "type": "Prio3Aes128CountVec",
            "length": format!("{length}"),
        }),
        VdafInstance::Prio3Aes128Sum { bits } => json!({
            "type": "Prio3Aes128Sum",
            "bits": format!("{bits}"),
        }),
        VdafInstance::Prio3Aes128Histogram { buckets } => {
            let buckets = Value::Array(
                buckets
                    .iter()
                    .map(|value| Value::String(format!("{value}")))
                    .collect(),
            );
            json!({
                "type": "Prio3Aes128Histogram",
                "buckets": buckets,
            })
        }
        _ => panic!("VDAF {vdaf:?} is not yet supported"),
    }
}

/// This represents a container image that implements the client role of
/// draft-dcook-ppm-dap-interop-test-design, for use with [`testcontainers`].
#[derive(Clone)]
pub struct InteropClient {
    name: String,
    tag: String,
}

impl InteropClient {
    /// By default, this creates an object referencing the latest divviup-ts interoperation test
    /// container image (for the correct DAP version). If the environment variable
    /// `DIVVIUP_TS_INTEROP_CONTAINER is set to a name and tag, then that image will be used
    /// instead.
    pub fn divviup_ts() -> InteropClient {
        if let Ok(value) = env::var("DIVVIUP_TS_INTEROP_CONTAINER") {
            if let Some((name, tag)) = value.rsplit_once(':') {
                InteropClient {
                    name: name.to_string(),
                    tag: tag.to_string(),
                }
            } else {
                InteropClient {
                    name: value.to_string(),
                    tag: "latest".to_string(),
                }
            }
        } else {
            InteropClient {
                name: "us-west2-docker.pkg.dev/divviup-artifacts-public/divviup-ts/divviup_ts_interop_client".to_string(),
                tag: "dap-draft-04@sha256:ad6fa3f6fa6f732ccf8291692e250ffa0cc50acd31bb393d98ebaec0f1d2f48c".to_string(),
            }
        }
    }
}

impl Image for InteropClient {
    type Args = ();

    fn name(&self) -> String {
        self.name.clone()
    }

    fn tag(&self) -> String {
        self.tag.clone()
    }

    fn ready_conditions(&self) -> Vec<testcontainers::core::WaitFor> {
        Vec::from([WaitFor::Healthcheck])
    }
}

/// This selects which DAP client implementation will be used in an integration test.
pub enum ClientBackend<'a> {
    /// Uploads reports using `janus-client` as a library.
    InProcess,
    /// Uploads reports by starting a containerized client implementation, and sending it requests
    /// using draft-dcook-ppm-dap-interop-test-design.
    Container {
        container_client: &'a Cli,
        container_image: InteropClient,
        network: &'a str,
    },
}

impl<'a> ClientBackend<'a> {
    pub async fn build<V>(
        &self,
        task: &Task,
        aggregator_endpoints: Vec<Url>,
        vdaf: V,
    ) -> anyhow::Result<ClientImplementation<'a, V>>
    where
        V: vdaf::Client + InteropClientEncoding,
        for<'b> Vec<u8>: From<&'b V::AggregateShare>,
    {
        match self {
            ClientBackend::InProcess => {
                ClientImplementation::new_in_process(task, aggregator_endpoints, vdaf)
                    .await
                    .map_err(Into::into)
            }
            ClientBackend::Container {
                container_client,
                container_image,
                network,
            } => Ok(ClientImplementation::new_container(
                container_client,
                container_image.clone(),
                network,
                task,
                vdaf,
            )),
        }
    }
}

pub struct ContainerClientImplementation<'d, V>
where
    V: vdaf::Client,
    for<'a> Vec<u8>: From<&'a V::AggregateShare>,
{
    _container: ContainerLogsDropGuard<'d, InteropClient>,
    leader: Url,
    helper: Url,
    task_id: TaskId,
    time_precision: Duration,
    vdaf: V,
    vdaf_instance: VdafInstance,
    host_port: u16,
    http_client: reqwest::Client,
}

/// A DAP client implementation, specialized to work with a particular VDAF. See also
/// [`ClientBackend`].
pub enum ClientImplementation<'d, V>
where
    V: vdaf::Client,
    for<'a> Vec<u8>: From<&'a V::AggregateShare>,
{
    InProcess { client: Client<V, RealClock> },
    Container(Box<ContainerClientImplementation<'d, V>>),
}

impl<'d, V> ClientImplementation<'d, V>
where
    V: vdaf::Client + InteropClientEncoding,
    for<'a> Vec<u8>: From<&'a V::AggregateShare>,
{
    pub async fn new_in_process(
        task: &Task,
        aggregator_endpoints: Vec<Url>,
        vdaf: V,
    ) -> Result<ClientImplementation<'static, V>, janus_client::Error> {
        let client_parameters =
            ClientParameters::new(*task.id(), aggregator_endpoints, *task.time_precision());
        let http_client = default_http_client()?;
        let leader_config =
            aggregator_hpke_config(&client_parameters, &Role::Leader, task.id(), &http_client)
                .await?;
        let helper_config =
            aggregator_hpke_config(&client_parameters, &Role::Helper, task.id(), &http_client)
                .await?;
        let client = Client::new(
            client_parameters,
            vdaf,
            RealClock::default(),
            &http_client,
            leader_config,
            helper_config,
        );
        Ok(ClientImplementation::InProcess { client })
    }

    pub fn new_container(
        container_client: &'d Cli,
        container_image: InteropClient,
        network: &str,
        task: &Task,
        vdaf: V,
    ) -> Self {
        let random_part = hex::encode(random::<[u8; 4]>());
        let client_container_name = format!("client-{random_part}");
        let container = container_client.run(
            RunnableImage::from(container_image)
                .with_network(network)
                .with_container_name(client_container_name),
        );
        let container = ContainerLogsDropGuard::new(container);
        let host_port = container.get_host_port_ipv4(8080);
        let http_client = reqwest::Client::new();
        ClientImplementation::Container(Box::new(ContainerClientImplementation {
            _container: container,
            leader: task.aggregator_endpoints()[Role::Leader.index().unwrap()].clone(),
            helper: task.aggregator_endpoints()[Role::Helper.index().unwrap()].clone(),
            task_id: *task.id(),
            time_precision: *task.time_precision(),
            vdaf,
            vdaf_instance: task.vdaf().clone(),
            host_port,
            http_client,
        }))
    }

    pub async fn upload(&self, measurement: &V::Measurement) -> anyhow::Result<()> {
        match self {
            ClientImplementation::InProcess { client } => {
                client.upload(measurement).await.map_err(Into::into)
            }
            ClientImplementation::Container(inner) => {
                let task_id_encoded = URL_SAFE_NO_PAD.encode(inner.task_id.get_encoded());
                let upload_response = inner
                    .http_client
                    .post(format!(
                        "http://127.0.0.1:{}/internal/test/upload",
                        inner.host_port
                    ))
                    .json(&json!({
                        "task_id": task_id_encoded,
                        "leader": inner.leader,
                        "helper": inner.helper,
                        "vdaf": json_encode_vdaf(&inner.vdaf_instance),
                        "measurement": inner.vdaf.json_encode_measurement(measurement),
                        "time_precision": inner.time_precision.as_seconds(),
                    }))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Value>()
                    .await?;
                match upload_response.get("status") {
                    Some(status) if status == "success" => Ok(()),
                    Some(status) => Err(anyhow!(
                        "upload request got {status} status, error is {:?}",
                        upload_response.get("error")
                    )),
                    None => Err(anyhow!("upload response is missing \"status\"")),
                }
            }
        }
    }
}
