#![cfg(feature = "in-cluster")]

use crate::common::{submit_measurements_and_verify_aggregate, test_task_builder};
use divviup_client::{
    Client, DivviupClient, Histogram, HpkeConfig, NewAggregator, NewSharedAggregator, NewTask, Vdaf,
};
use janus_aggregator_core::task::QueryType;
use janus_core::{
    auth_tokens::AuthenticationToken,
    test_util::{
        install_test_trace_subscriber,
        kubernetes::{Cluster, PortForward},
    },
    vdaf::VdafInstance,
};
use janus_integration_tests::{client::ClientBackend, TaskParameters};
use janus_messages::TaskId;
use std::{env, str::FromStr};
use trillium_tokio::ClientConfig;
use url::Url;

struct InClusterJanusPair {
    /// Task parameters needed by the client and collector, for the task configured in both Janus
    /// aggregators.
    task_parameters: TaskParameters,

    /// Handle to the leader's resources, which are released on drop.
    leader: InClusterJanus,
    /// Handle to the helper's resources, which are released on drop.
    helper: InClusterJanus,
}

impl InClusterJanusPair {
    /// Set up a new DAP task, using the given VDAF and query type, in a pair of existing Janus
    /// instances in a Kubernetes cluster. `divviup-api` is used to configure the task in each Janus
    /// instance. The following environment variables must be set.
    ///
    ///  - `JANUS_E2E_KUBE_CONFIG_PATH`: The path to a kubeconfig file, containing the information
    ///    needed to connect to the cluster.
    ///  - `JANUS_E2E_KUBECTL_CONTEXT_NAME`: The name of a context in the kubeconfig file.
    ///  - `JANUS_E2E_LEADER_NAMESPACE`: The Kubernetes namespace where the DAP leader is deployed.
    ///  - `JANUS_E2E_LEADER_AGGREGATOR_API_AUTH_TOKEN`: Credential with which requests to the
    ///     leader's aggregator API are authenticated.
    ///  - `JANUS_E2E_HELPER_NAMESPACE`: The Kubernetes namespace where the DAP helper is deployed.
    ///  - `JANUS_E2E_HELPER_AGGREGATOR_API_AUTH_TOKEN`: Credential with which requests to the
    ///     helper's aggregator API are authenticated.
    ///  - `JANUS_E2E_DIVVIUP_API_NAMESPACE`: The Kubernetes namespace where `divviup-api` is
    ///     deployed.
    async fn new(vdaf: VdafInstance, query_type: QueryType) -> Self {
        let (
            kubeconfig_path,
            kubectl_context_name,
            leader_namespace,
            leader_aggregator_api_auth_token,
            helper_namespace,
            helper_aggregator_api_auth_token,
            divviup_api_namespace,
        ) = match (
            env::var("JANUS_E2E_KUBE_CONFIG_PATH"),
            env::var("JANUS_E2E_KUBECTL_CONTEXT_NAME"),
            env::var("JANUS_E2E_LEADER_NAMESPACE"),
            env::var("JANUS_E2E_LEADER_AGGREGATOR_API_AUTH_TOKEN"),
            env::var("JANUS_E2E_HELPER_NAMESPACE"),
            env::var("JANUS_E2E_HELPER_AGGREGATOR_API_AUTH_TOKEN"),
            env::var("JANUS_E2E_DIVVIUP_API_NAMESPACE"),
        ) {
            (
                Ok(kubeconfig_path),
                Ok(kubectl_context_name),
                Ok(leader_namespace),
                Ok(leader_aggregator_api_auth_token),
                Ok(helper_namespace),
                Ok(helper_aggregator_api_auth_token),
                Ok(divviup_api_namespace),
            ) => (
                kubeconfig_path,
                kubectl_context_name,
                leader_namespace,
                leader_aggregator_api_auth_token,
                helper_namespace,
                helper_aggregator_api_auth_token,
                divviup_api_namespace,
            ),
            _ => panic!("missing or invalid environment variables"),
        };

        let cluster = Cluster::new(&kubeconfig_path, &kubectl_context_name);

        let (mut task_parameters, task_builder) = test_task_builder(vdaf, query_type);
        let task = task_builder.with_min_batch_size(100).build();
        task_parameters.min_batch_size = 100;

        // From outside the cluster, the aggregators are reached at a dynamically allocated port on
        // localhost. When the aggregators talk to each other, they do so in the cluster's network,
        // so they need the in-cluster DNS name of the other aggregator, and they can use well-known
        // service port numbers.

        let port_forward = cluster
            .forward_port(&divviup_api_namespace, "divviup-api", 80)
            .await;
        let port = port_forward.local_port();

        let mut divviup_api = DivviupClient::new(
            "DUATignored".into(),
            Client::new(ClientConfig::new()).with_default_pool(),
        );
        divviup_api.set_url(format!("http://127.0.0.1:{port}").parse().unwrap());

        // Create an account first. (We should be implicitly logged in as a testing user already,
        // assuming divviup-api was built with the integration-testing feature)
        let account = divviup_api
            .create_account("Integration test account")
            .await
            .unwrap();

        // Pair the aggregators. The same Janus instances will get paired multiple times across
        // multiple tests, but it's to a different divviup-api account each time, so that's
        // harmless. The leader aggregator is paired as a *global* aggregator using the admin
        // endpoint. We do this for two reasons:
        //
        // - setting up tasks with one global aggregator and one per-account aggregator is most
        //   representative of the subscriber use cases Divvi Up supports,
        let paired_leader_aggregator = divviup_api
            .create_shared_aggregator(NewSharedAggregator {
                name: "leader".to_string(),
                api_url: Self::in_cluster_aggregator_api_url(&leader_namespace),
                bearer_token: leader_aggregator_api_auth_token,
                is_first_party: true,
            })
            .await
            .unwrap();

        let paired_helper_aggregator = divviup_api
            .create_aggregator(
                account.id,
                NewAggregator {
                    name: "helper".to_string(),
                    api_url: Self::in_cluster_aggregator_api_url(&helper_namespace),
                    bearer_token: helper_aggregator_api_auth_token,
                },
            )
            .await
            .unwrap();

        let hpke_config = task.collector_hpke_keypair().config();
        let collector_credential = divviup_api
            .create_collector_credential(
                account.id,
                &HpkeConfig::new(
                    u8::from(*hpke_config.id()).into(),
                    u16::from(*hpke_config.kem_id()).try_into().unwrap(),
                    u16::from(*hpke_config.kdf_id()).try_into().unwrap(),
                    u16::from(*hpke_config.aead_id()).try_into().unwrap(),
                    hpke_config.public_key().as_ref().to_vec().into(),
                ),
                Some("Integration test key"),
            )
            .await
            .unwrap();

        let provision_task_request = NewTask {
            name: "Integration test task".to_string(),
            leader_aggregator_id: paired_leader_aggregator.id,
            helper_aggregator_id: paired_helper_aggregator.id,
            vdaf: match task.vdaf().to_owned() {
                VdafInstance::Prio3Count => Vdaf::Count,
                VdafInstance::Prio3Sum { bits } => Vdaf::Sum {
                    bits: bits.try_into().unwrap(),
                },
                VdafInstance::Prio3SumVec {
                    bits,
                    length,
                    chunk_length,
                } => Vdaf::SumVec {
                    bits: bits.try_into().unwrap(),
                    length: length.try_into().unwrap(),
                    chunk_length: Some(chunk_length.try_into().unwrap()),
                },
                VdafInstance::Prio3Histogram {
                    length,
                    chunk_length,
                } => Vdaf::Histogram(Histogram::Length {
                    length: length.try_into().unwrap(),
                    chunk_length: Some(chunk_length.try_into().unwrap()),
                }),
                VdafInstance::Prio3CountVec {
                    length,
                    chunk_length,
                } => Vdaf::CountVec {
                    length: length.try_into().unwrap(),
                    chunk_length: Some(chunk_length.try_into().unwrap()),
                },
                other => panic!("unsupported vdaf {other:?}"),
            },
            min_batch_size: task.min_batch_size(),
            max_batch_size: match task.query_type() {
                QueryType::TimeInterval => None,
                QueryType::FixedSize { max_batch_size, .. } => Some(*max_batch_size),
            },
            time_precision_seconds: task.time_precision().as_seconds(),
            collector_credential_id: collector_credential.id,
        };

        // Provision the task into both aggregators via divviup-api
        let provisioned_task = divviup_api
            .create_task(account.id, provision_task_request)
            .await
            .unwrap();

        // Update the task parameters with the ID and collector auth token from divviup-api.
        task_parameters.task_id = TaskId::from_str(&provisioned_task.id).unwrap();
        task_parameters.collector_auth_token = AuthenticationToken::new_bearer_token_from_string(
            collector_credential.token.clone().unwrap(),
        )
        .unwrap();

        Self {
            task_parameters,
            leader: InClusterJanus::new(&cluster, &leader_namespace).await,
            helper: InClusterJanus::new(&cluster, &helper_namespace).await,
        }
    }

    fn in_cluster_aggregator_api_url(namespace: &str) -> Url {
        Url::parse(&format!(
            "http://aggregator.{namespace}.svc.cluster.local:80/aggregator-api/"
        ))
        .unwrap()
    }
}

struct InClusterJanus {
    aggregator_port_forward: PortForward,
}

impl InClusterJanus {
    /// Set up a port forward to an existing Janus instance in a Kubernetes cluster, and provision a
    /// DAP task in it via divviup-api.
    async fn new(cluster: &Cluster, aggregator_namespace: &str) -> Self {
        let aggregator_port_forward = cluster
            .forward_port(aggregator_namespace, "aggregator", 80)
            .await;
        Self {
            aggregator_port_forward,
        }
    }

    fn port(&self) -> u16 {
        self.aggregator_port_forward.local_port()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_count() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair =
        InClusterJanusPair::new(VdafInstance::Prio3Count, QueryType::TimeInterval).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "in_cluster_count",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_sum() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair =
        InClusterJanusPair::new(VdafInstance::Prio3Sum { bits: 16 }, QueryType::TimeInterval).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "in_cluster_sum",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_histogram() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair = InClusterJanusPair::new(
        VdafInstance::Prio3Histogram {
            length: 4,
            chunk_length: 2,
        },
        QueryType::TimeInterval,
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "in_cluster_histogram",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn in_cluster_fixed_size() {
    install_test_trace_subscriber();

    // Start port forwards and set up task.
    let janus_pair = InClusterJanusPair::new(
        VdafInstance::Prio3Count,
        QueryType::FixedSize {
            max_batch_size: 110,
            batch_time_window_size: None,
        },
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "in_cluster_fixed_size",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

#[cfg(feature = "in-cluster-rate-limits")]
mod rate_limits {
    use super::InClusterJanusPair;
    use assert_matches::assert_matches;
    use http::Method;
    use janus_aggregator_core::task::QueryType;
    use janus_core::{test_util::install_test_trace_subscriber, vdaf::VdafInstance};
    use janus_messages::{AggregationJobId, CollectionJobId, TaskId};
    use rand::random;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use std::{
        env,
        fs::File,
        sync::{Arc, OnceLock},
        time::Duration,
    };
    use tokio::sync::Semaphore;
    use url::Url;

    /// Configuration for the rate limit test. We need to know the QPS and the window over which
    /// it is enforced so that we can send the appropriate number of requests. We load this config
    /// from a file so that an integration test harness that knows what rate limits have been
    /// deployed to the cluster we test against can set the values.
    #[derive(Deserialize)]
    struct TestConfig {
        rate_limit_excess: f64,
        window: u64,
        upload_qps: u64,
        aggregation_job_qps: u64,
        collection_job_qps: u64,
    }

    impl TestConfig {
        fn load() -> &'static Self {
            static CONFIG: OnceLock<TestConfig> = OnceLock::new();

            CONFIG.get_or_init(|| {
                serde_json::from_reader(
                    File::open(env::var("JANUS_E2E_RATE_LIMIT_TEST_CONFIG").unwrap()).unwrap(),
                )
                .unwrap()
            })
        }
    }

    struct RequestUrlParameters<'a> {
        leader_url: &'a Url,
        helper_url: &'a Url,
        first_task_id: &'a TaskId,
        second_task_id: &'a TaskId,
    }

    async fn run_rate_limit_test(
        request_url_maker: &dyn Fn(&RequestUrlParameters) -> (Url, Url),
        rate_limit_picker: &dyn Fn(&TestConfig) -> u64,
        method: Method,
    ) {
        install_test_trace_subscriber();
        let test_config = TestConfig::load();

        let janus_pair =
            InClusterJanusPair::new(VdafInstance::Prio3Count, QueryType::TimeInterval).await;

        let (leader_url, helper_url) = janus_pair
            .task_parameters
            .endpoint_fragments
            .endpoints_for_host_client(janus_pair.leader.port(), janus_pair.helper.port());
        let other_task_id = random();

        // Send requests to two different tasks, to prove that rate limits are per-task ID. It
        // doesn't matter that one of the tasks doesn't exist for purposes of rate limits.
        let (first_request_url, second_request_url) = request_url_maker(&RequestUrlParameters {
            leader_url: &leader_url,
            helper_url: &helper_url,
            first_task_id: &janus_pair.task_parameters.task_id,
            second_task_id: &other_task_id,
        });
        let rate_limit = rate_limit_picker(&test_config);
        let rate_limit_excess = test_config.rate_limit_excess;
        let total_requests_count =
            ((1.0 + rate_limit_excess) * (rate_limit * test_config.window) as f64) as u64;

        let mut acceptable_status_count = 0;
        let mut too_many_requests_count = 0;
        let mut last_retry_after = None;
        let client = reqwest::Client::builder().build().unwrap();

        // Send ten requests at a time, because otherwise the kubectl port-forward gets overwhelmed
        let semaphore = Arc::new(Semaphore::new(10));
        let mut handles = Vec::new();
        for _ in 0..total_requests_count {
            for url in [first_request_url.clone(), second_request_url.clone()] {
                let (client, method, semaphore) =
                    (client.clone(), method.clone(), semaphore.clone());
                handles.push(tokio::spawn(async move {
                    let _permit = semaphore.acquire_owned().await.unwrap();
                    // We avoid using janus_client here because we don't want it to automatically
                    // retry on HTTP 429 for us.
                    let response = client.request(method, url).send().await.unwrap();

                    (
                        response.headers().get("retry-after").cloned(),
                        response.status(),
                    )
                }));
            }
        }

        for handle in handles {
            let (retry_after, status) = handle.await.unwrap();
            // Every request this test send should get rejected due to a missing body if it gets
            // past the rate limiter.
            if status == StatusCode::BAD_REQUEST {
                assert!(retry_after.is_none());
                acceptable_status_count += 1
            } else if status == StatusCode::TOO_MANY_REQUESTS {
                assert_matches!(retry_after, Some(retry_after) => {
                    let retry_after = retry_after.to_str().unwrap().parse::<u64>().unwrap();
                    assert!(retry_after <= test_config.window);
                    last_retry_after = Some(retry_after);
                });
                too_many_requests_count += 1
            } else {
                panic!("unexpected status {status:?}");
            }
        }

        let ratio = too_many_requests_count as f64
            / (acceptable_status_count + too_many_requests_count) as f64;
        // We expect some exact percentage of requests to be rejected with HTTP 429, but allow a
        // margin for error to account for cases where the test takes more than a second to run, or
        // errors introduced by Caddy distributed rate limiting.
        let expected_429_rate = rate_limit_excess / (1.0 + rate_limit_excess);
        assert!(
            ratio > expected_429_rate - 0.05 && ratio <= expected_429_rate + 0.05,
            "ratio: {ratio} expected 429 rate: {expected_429_rate} \
            count of HTTP 429: {too_many_requests_count} \
            count of HTTP 400: {acceptable_status_count}",
        );

        let last_retry_after = assert_matches!(last_retry_after, Some(l) => l);

        // Wait for prescribed time to elapse and then try again. Requests should go through.
        std::thread::sleep(Duration::from_secs(last_retry_after));

        for url in [first_request_url.clone(), second_request_url.clone()] {
            let method = method.clone();
            let response = client.request(method, url).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(response.headers().get("retry-after").is_none());
        }
    }

    #[tokio::test]
    async fn upload() {
        run_rate_limit_test(
            &|RequestUrlParameters {
                  leader_url,
                  first_task_id,
                  second_task_id,
                  ..
              }| {
                (
                    leader_url
                        .join(&format!("tasks/{first_task_id}/reports"))
                        .unwrap(),
                    leader_url
                        .join(&format!("tasks/{second_task_id}/reports"))
                        .unwrap(),
                )
            },
            &|test_config| test_config.upload_qps,
            Method::PUT,
        )
        .await
    }

    #[rstest::rstest]
    #[case::put(Method::PUT)]
    #[case::post(Method::POST)]
    #[case::delete(Method::DELETE)]
    #[tokio::test]
    async fn collection_job(#[case] method: Method) {
        run_rate_limit_test(
            &|RequestUrlParameters {
                  leader_url,
                  first_task_id,
                  second_task_id,
                  ..
              }| {
                let job_id: CollectionJobId = random();

                (
                    leader_url
                        .join(&format!("tasks/{first_task_id}/collection_jobs/{job_id}"))
                        .unwrap(),
                    leader_url
                        .join(&format!("tasks/{second_task_id}/collection_jobs/{job_id}"))
                        .unwrap(),
                )
            },
            &|test_config| test_config.collection_job_qps,
            method,
        )
        .await
    }

    #[rstest::rstest]
    #[case::put(Method::PUT)]
    #[case::post(Method::POST)]
    #[tokio::test]
    async fn aggregation_job_put(#[case] method: Method) {
        run_rate_limit_test(
            &|RequestUrlParameters {
                  helper_url,
                  first_task_id,
                  second_task_id,
                  ..
              }| {
                let job_id: AggregationJobId = random();
                (
                    helper_url
                        .join(&format!("tasks/{first_task_id}/aggregation_jobs/{job_id}"))
                        .unwrap(),
                    helper_url
                        .join(&format!("tasks/{second_task_id}/aggregation_jobs/{job_id}"))
                        .unwrap(),
                )
            },
            &|test_config| test_config.aggregation_job_qps,
            method,
        )
        .await
    }

    #[tokio::test]
    async fn aggregate_share_post() {
        run_rate_limit_test(
            &|RequestUrlParameters {
                  helper_url,
                  first_task_id,
                  second_task_id,
                  ..
              }| {
                (
                    helper_url
                        .join(&format!("tasks/{first_task_id}/aggregate_shares"))
                        .unwrap(),
                    helper_url
                        .join(&format!("tasks/{second_task_id}/aggregate_shares"))
                        .unwrap(),
                )
            },
            &|test_config| test_config.collection_job_qps,
            Method::POST,
        )
        .await
    }
}
