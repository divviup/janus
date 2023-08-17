use anyhow::anyhow;
use http::{
    header::{ACCEPT, CONTENT_TYPE},
    Method,
};
use janus_core::{task::VdafInstance, test_util::kubernetes::PortForward};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use url::Url;

/// Representation of a `divviup-api` account.
#[derive(Deserialize)]
pub struct Account {
    id: String,
}

/// Representation of a VDAF in `divviup-api`.
#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ApiVdaf {
    /// Corresponds to Prio3Count
    Count,
    Histogram {
        buckets: Vec<u64>,
    },
    Sum {
        bits: u32,
    },
}

impl TryFrom<&VdafInstance> for ApiVdaf {
    type Error = anyhow::Error;

    fn try_from(vdaf: &VdafInstance) -> Result<Self, Self::Error> {
        match vdaf {
            VdafInstance::Prio3Aes128Count => Ok(ApiVdaf::Count),
            VdafInstance::Prio3Aes128Sum { bits } => Ok(ApiVdaf::Sum { bits: *bits }),
            VdafInstance::Prio3Aes128Histogram { buckets } => Ok(ApiVdaf::Histogram {
                buckets: buckets.clone(),
            }),
            _ => Err(anyhow!("unsupported VDAF: {vdaf:?}")),
        }
    }
}

#[derive(Serialize)]
pub struct NewTaskRequest {
    pub name: String,
    pub leader_aggregator_id: String,
    pub helper_aggregator_id: String,
    pub vdaf: ApiVdaf,
    pub min_batch_size: u64,
    pub max_batch_size: Option<u64>,
    pub expiration: String,
    pub time_precision_seconds: u64,
    pub hpke_config_id: String,
}

/// Representation of a DAP task in responses from divviup-api. This application ignores several
/// fields that we never use.
#[derive(Deserialize)]
pub struct DivviUpApiTask {
    /// DAP task ID
    pub id: String,
}

/// Request to pair an aggregator with divviup-api
#[derive(Serialize)]
pub struct NewAggregatorRequest {
    pub name: String,
    pub api_url: String,
    /// Bearer token for authenticating requests to this aggregator's aggregator API
    pub bearer_token: String,
}

/// Representation of an aggregator in responses from divviup-api. This application ignores several
/// fields that we never use.
#[derive(Deserialize)]
pub struct DivviUpAggregator {
    pub id: String,
    pub dap_url: Url,
}

/// Request to create an HPKE config in divviup-api.
#[derive(Serialize)]
pub struct NewHpkeConfigRequest {
    pub name: String,
    pub contents: String,
}

/// Representation of an HPKE config in responses from divviup-api. This application ignores most
/// fields that we never use.
#[derive(Deserialize)]
pub struct DivviUpHpkeConfig {
    pub id: String,
}

/// Representation of a collector auth token in divviup-api.
#[derive(Deserialize)]
pub struct CollectorAuthToken {
    /// Type of the authentication token. Always "Bearer" in divviup-api.
    pub r#type: String,
    /// Encoded value of the token. The encoding is opaque to divviup-api.
    pub token: String,
}

const DIVVIUP_CONTENT_TYPE: &str = "application/vnd.divviup+json;version=0.1";

pub struct DivviupApiClient {
    port_forward: PortForward,
    client: reqwest::Client,
}

impl DivviupApiClient {
    pub fn new(port_forward: PortForward) -> Self {
        Self {
            port_forward,
            client: reqwest::Client::new(),
        }
    }

    pub async fn make_request<B: Serialize, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<B>,
        request_description: &str,
    ) -> R {
        let mut builder = self
            .client
            .request(
                method,
                format!(
                    "http://127.0.0.1:{}/api/{path}",
                    self.port_forward.local_port()
                ),
            )
            .header(CONTENT_TYPE, DIVVIUP_CONTENT_TYPE)
            .header(ACCEPT, DIVVIUP_CONTENT_TYPE);
        if let Some(body) = body {
            let body_string = serde_json::to_string(&body).unwrap();
            builder = builder.body(body_string);
        }

        let resp = builder.send().await.unwrap();
        let status = resp.status();
        if !status.is_success() {
            let resp_text = resp.text().await;
            panic!("{request_description} request returned status code {status}, {resp_text:?}");
        }

        resp.json().await.unwrap()
    }

    pub async fn create_account(&self) -> Account {
        self.make_request(
            Method::POST,
            "accounts",
            Some(json!({"name": "Integration test account"})),
            "Account creation",
        )
        .await
    }

    pub async fn pair_global_aggregator(
        &self,
        request: &NewAggregatorRequest,
    ) -> DivviUpAggregator {
        self.make_request(
            Method::POST,
            "aggregators",
            Some(request),
            "Global aggregator pairing",
        )
        .await
    }

    pub async fn pair_aggregator(
        &self,
        account: &Account,
        request: &NewAggregatorRequest,
    ) -> DivviUpAggregator {
        self.make_request(
            Method::POST,
            &format!("accounts/{}/aggregators", account.id),
            Some(request),
            "Aggregator pairing",
        )
        .await
    }

    pub async fn create_hpke_config(
        &self,
        account: &Account,
        request: &NewHpkeConfigRequest,
    ) -> DivviUpHpkeConfig {
        self.make_request(
            Method::POST,
            &format!("accounts/{}/hpke_configs", account.id),
            Some(request),
            "HPKE config creation",
        )
        .await
    }

    pub async fn create_task(&self, account: &Account, request: &NewTaskRequest) -> DivviUpApiTask {
        self.make_request(
            Method::POST,
            &format!("accounts/{}/tasks", account.id),
            Some(request),
            "Task creation",
        )
        .await
    }

    pub async fn list_collector_auth_tokens(
        &self,
        task: &DivviUpApiTask,
    ) -> Vec<CollectorAuthToken> {
        // Hack: we must choose some specialization for the B type despite the request having no
        // Body
        self.make_request::<String, _>(
            Method::GET,
            &format!("tasks/{}/collector_auth_tokens", task.id),
            None,
            "List collector auth tokens",
        )
        .await
    }
}
