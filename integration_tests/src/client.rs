use crate::TaskParameters;
use anyhow::anyhow;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use janus_client::Client;
use janus_core::vdaf::{Prio3SumVecField64MultiproofHmacSha256Aes128, VdafInstance};
use janus_interop_binaries::{get_rust_log_level, ContainerLogsDropGuard};
use janus_messages::{Duration, TaskId, Time};
use prio::{
    codec::Encode,
    field::Field64,
    flp::gadgets::{Mul, ParallelSumGadget},
    vdaf::{
        self, dummy,
        prio3::{Prio3Count, Prio3HistogramMultithreaded, Prio3Sum, Prio3SumVecMultithreaded},
    },
};
use rand::random;
use serde_json::{json, Value};
use std::env;
use testcontainers::{
    core::{wait::HealthWaitStrategy, WaitFor},
    runners::AsyncRunner,
    ContainerRequest, Image, ImageExt,
};
use url::Url;

/// Extension trait to encode measurements for VDAFs as JSON objects, according to
/// draft-dcook-ppm-dap-interop-test-design.
pub trait InteropClientEncoding: vdaf::Client<16> {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value;
}

impl InteropClientEncoding for Prio3Count {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        if *measurement {
            Value::String("0".into())
        } else {
            Value::String("1".into())
        }
    }
}

impl InteropClientEncoding for Prio3Sum {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::String(format!("{measurement}"))
    }
}

impl InteropClientEncoding for Prio3HistogramMultithreaded {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::String(format!("{measurement}"))
    }
}

impl InteropClientEncoding for Prio3SumVecMultithreaded {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::Array(
            measurement
                .iter()
                .map(|value| Value::String(format!("{value}")))
                .collect(),
        )
    }
}

impl<PS> InteropClientEncoding for Prio3SumVecField64MultiproofHmacSha256Aes128<PS>
where
    PS: ParallelSumGadget<Field64, Mul<Field64>> + Eq + 'static,
{
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::Array(
            measurement
                .iter()
                .map(|value| Value::String(format!("{value}")))
                .collect(),
        )
    }
}

impl InteropClientEncoding for dummy::Vdaf {
    fn json_encode_measurement(&self, measurement: &Self::Measurement) -> Value {
        Value::String(format!("{measurement}"))
    }
}

fn json_encode_vdaf(vdaf: &VdafInstance) -> Value {
    match vdaf {
        VdafInstance::Prio3Count => json!({
            "type": "Prio3Count"
        }),
        VdafInstance::Prio3Sum { bits } => json!({
            "type": "Prio3Sum",
            "bits": format!("{bits}"),
        }),
        VdafInstance::Prio3SumVec {
            bits,
            length,
            chunk_length,
            dp_strategy: _,
        } => json!({
            "type": "Prio3SumVec",
            "bits": format!("{bits}"),
            "length": format!("{length}"),
            "chunk_length": format!("{chunk_length}"),
        }),
        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs,
            bits,
            length,
            chunk_length,
            dp_strategy: _,
        } => json!({
            "type": "Prio3SumVecField64MultiproofHmacSha256Aes128",
            "proofs": format!("{proofs}"),
            "bits": format!("{bits}"),
            "length": format!("{length}"),
            "chunk_length": format!("{chunk_length}"),
        }),
        VdafInstance::Prio3Histogram {
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            json!({
                "type": "Prio3Histogram",
                "length": format!("{length}"),
                "chunk_length": format!("{chunk_length}"),
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
                name: "us-west2-docker.pkg.dev/divviup-artifacts-public/divviup-ts/\
                       divviup_ts_interop_client"
                    .to_string(),
                tag: "e2bd57d@sha256:\
                      ea32ec6d1e6522d4282b644e9885aeb30a0a92877f73e27424e9e00844b9a80c"
                    .to_string(),
            }
        }
    }
}

impl Image for InteropClient {
    fn name(&self) -> &str {
        &self.name
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn ready_conditions(&self) -> Vec<testcontainers::core::WaitFor> {
        Vec::from([WaitFor::Healthcheck(HealthWaitStrategy::new())])
    }
}

/// This selects which DAP client implementation will be used in an integration test.
pub enum ClientBackend<'a> {
    /// Uploads reports using `janus-client` as a library.
    InProcess,
    /// Uploads reports by starting a containerized client implementation, and sending it requests
    /// using draft-dcook-ppm-dap-interop-test-design.
    Container {
        container_image: InteropClient,
        network: &'a str,
    },
}

impl<'a> ClientBackend<'a> {
    pub async fn build<V>(
        &self,
        test_name: &str,
        task_parameters: &TaskParameters,
        (leader_port, helper_port): (u16, u16),
        vdaf: V,
    ) -> anyhow::Result<ClientImplementation<V>>
    where
        V: vdaf::Client<16> + InteropClientEncoding,
    {
        match self {
            ClientBackend::InProcess => ClientImplementation::new_in_process(
                task_parameters,
                (leader_port, helper_port),
                vdaf,
            )
            .await
            .map_err(Into::into),
            ClientBackend::Container {
                container_image,
                network,
            } => Ok(ClientImplementation::new_container(
                test_name,
                container_image.clone(),
                network,
                task_parameters,
                vdaf,
            )
            .await),
        }
    }
}

pub struct ContainerClientImplementation<V>
where
    V: vdaf::Client<16>,
{
    _container: ContainerLogsDropGuard<InteropClient>,
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
pub enum ClientImplementation<V>
where
    V: vdaf::Client<16>,
{
    InProcess { client: Client<V> },
    Container(Box<ContainerClientImplementation<V>>),
}

impl<V> ClientImplementation<V>
where
    V: vdaf::Client<16> + InteropClientEncoding,
{
    pub async fn new_in_process(
        task_parameters: &TaskParameters,
        (leader_port, helper_port): (u16, u16),
        vdaf: V,
    ) -> Result<ClientImplementation<V>, janus_client::Error> {
        let (leader_aggregator_endpoint, helper_aggregator_endpoint) = task_parameters
            .endpoint_fragments
            .endpoints_for_host_client(leader_port, helper_port);
        let mut builder = Client::builder(
            task_parameters.task_id,
            leader_aggregator_endpoint,
            helper_aggregator_endpoint,
            task_parameters.time_precision,
            vdaf,
        );

        if let Some(ohttp_config) = &task_parameters.endpoint_fragments.ohttp_config {
            builder = builder.with_ohttp_config(ohttp_config.clone());
        }

        let client = builder.build().await?;
        Ok(ClientImplementation::InProcess { client })
    }

    pub async fn new_container(
        test_name: &str,
        container_image: InteropClient,
        network: &str,
        task_parameters: &TaskParameters,
        vdaf: V,
    ) -> Self {
        let random_part = hex::encode(random::<[u8; 4]>());
        let client_container_name = format!("client-{random_part}");
        let container = ContainerLogsDropGuard::new_janus(
            test_name,
            ContainerRequest::from(container_image)
                .with_network(network)
                .with_env_var("RUST_LOG", get_rust_log_level())
                .with_container_name(client_container_name)
                .start()
                .await
                .unwrap(),
        );
        let host_port = container.get_host_port_ipv4(8080).await.unwrap();
        let http_client = reqwest::Client::new();
        let (leader_aggregator_endpoint, helper_aggregator_endpoint) = task_parameters
            .endpoint_fragments
            .endpoints_for_virtual_network_client();
        ClientImplementation::Container(Box::new(ContainerClientImplementation {
            _container: container,
            leader: leader_aggregator_endpoint,
            helper: helper_aggregator_endpoint,
            task_id: task_parameters.task_id,
            time_precision: task_parameters.time_precision,
            vdaf,
            vdaf_instance: task_parameters.vdaf.clone(),
            host_port,
            http_client,
        }))
    }

    pub async fn upload(&self, measurement: &V::Measurement, time: Time) -> anyhow::Result<()> {
        match self {
            ClientImplementation::InProcess { client } => client
                .upload_with_time(measurement, time)
                .await
                .map_err(Into::into),
            ClientImplementation::Container(inner) => {
                let task_id_encoded = URL_SAFE_NO_PAD.encode(inner.task_id.get_encoded().unwrap());
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
                        "time": time.as_seconds_since_epoch(),
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
