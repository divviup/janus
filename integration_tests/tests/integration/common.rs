use backoff::{future::retry, ExponentialBackoffBuilder};
use itertools::Itertools;
use janus_aggregator_core::task::{test_util::TaskBuilder, QueryType};
use janus_collector::{Collection, Collector};
use janus_core::{
    retries::test_util::test_http_request_exponential_backoff,
    time::{Clock, RealClock, TimeExt},
    vdaf::{new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128, VdafInstance},
};
use janus_integration_tests::{
    client::{ClientBackend, ClientImplementation, InteropClientEncoding},
    AggregatorEndpointFragments, EndpointFragments, TaskParameters,
};
use janus_messages::{
    problem_type::DapProblemType,
    query_type::{self, FixedSize},
    Duration, FixedSizeQuery, Interval, Query, Time,
};
use prio::{
    flp::gadgets::ParallelSumMultithreaded,
    vdaf::{self, dummy, prio3::Prio3},
};
use rand::{random, thread_rng, Rng};
use std::{iter, time::Duration as StdDuration};
use tokio::time::{self, sleep};
use url::Url;

/// Different contexts or test harnesses that integration tests may be run against, which require
/// different configuration customizations.
pub enum TestContext {
    /// Aggregators are running in a virtual network, like a Docker network or a Kind cluster.
    VirtualNetwork,
    /// Aggregators are running natively on the same host as the test driver.
    Host,
    /// Aggregators are running remotely, say in a staging environment.
    #[cfg(feature = "in-cluster")]
    Remote,
}

/// Configures the provided task builder to run in the provided test context, and constructs a
/// corresponding [`TaskParameters`].
pub fn build_test_task(
    mut task_builder: TaskBuilder,
    test_context: TestContext,
    collector_max_interval: time::Duration,
    collector_max_elapsed_time: time::Duration,
) -> (TaskParameters, TaskBuilder) {
    let (leader_endpoint, helper_endpoint, endpoint_fragments) = match test_context {
        TestContext::VirtualNetwork => {
            let endpoint_random_value = hex::encode(random::<[u8; 4]>());
            (
                Url::parse(&format!("http://leader-{endpoint_random_value}:8080/")).unwrap(),
                Url::parse(&format!("http://helper-{endpoint_random_value}:8080/")).unwrap(),
                EndpointFragments {
                    leader: AggregatorEndpointFragments::VirtualNetwork {
                        host: format!("leader-{endpoint_random_value}"),
                        path: "/".to_string(),
                    },
                    helper: AggregatorEndpointFragments::VirtualNetwork {
                        host: format!("helper-{endpoint_random_value}"),
                        path: "/".to_string(),
                    },
                    ohttp_config: None,
                },
            )
        }
        TestContext::Host => (
            Url::parse("http://invalid/").unwrap(),
            Url::parse("http://invalid/").unwrap(),
            EndpointFragments {
                leader: AggregatorEndpointFragments::Localhost {
                    path: "/".to_string(),
                },
                helper: AggregatorEndpointFragments::Localhost {
                    path: "/".to_string(),
                },
                ohttp_config: None,
            },
        ),
        #[cfg(feature = "in-cluster")]
        TestContext::Remote => (
            task_builder.leader_aggregator_endpoint().clone(),
            task_builder.helper_aggregator_endpoint().clone(),
            EndpointFragments {
                leader: AggregatorEndpointFragments::Remote {
                    url: task_builder.leader_aggregator_endpoint().clone(),
                },
                helper: AggregatorEndpointFragments::Remote {
                    url: task_builder.helper_aggregator_endpoint().clone(),
                },
                ohttp_config: None,
            },
        ),
    };

    task_builder = task_builder
        .with_leader_aggregator_endpoint(leader_endpoint)
        .with_helper_aggregator_endpoint(helper_endpoint)
        .with_min_batch_size(46)
        // The randomly generated auth tokens will only be used in the TestContext::VirtualNetwork
        // and TestContext::Host cases. They will be ignored in the TestContext::Remote case,
        // because the auth tokens will be provisioned via divviup-api, but it's harmless to set
        // them in the task builder.
        .with_dap_auth_aggregator_token()
        .with_dap_auth_collector_token();

    let task_parameters = TaskParameters {
        task_id: *task_builder.task_id(),
        endpoint_fragments,
        query_type: *task_builder.query_type(),
        vdaf: task_builder.vdaf().clone(),
        min_batch_size: task_builder.min_batch_size(),
        time_precision: *task_builder.time_precision(),
        collector_hpke_keypair: task_builder.collector_hpke_keypair().clone(),
        collector_auth_token: task_builder.collector_auth_token().clone(),
        collector_max_interval,
        collector_max_elapsed_time,
    };
    (task_parameters, task_builder)
}

/// A set of inputs and an expected output for a VDAF's aggregation.
pub struct AggregationTestCase<V>
where
    V: vdaf::Client<16> + vdaf::Collector,
{
    measurements: Vec<V::Measurement>,
    aggregation_parameter: V::AggregationParam,
    aggregate_result: V::AggregateResult,
}

pub async fn collect_generic<'a, V, Q>(
    collector: &Collector<V>,
    query: Query<Q>,
    aggregation_parameter: &V::AggregationParam,
) -> Result<Collection<V::AggregateResult, Q>, janus_collector::Error>
where
    V: vdaf::Client<16> + vdaf::Collector + InteropClientEncoding,
    Q: query_type::QueryType,
{
    // An extra retry loop is needed here because our collect request may race against the
    // aggregation job creator, which is responsible for assigning reports to batches in fixed-
    // size tasks.
    let backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(time::Duration::from_millis(500))
        .with_max_interval(time::Duration::from_millis(500))
        .with_max_elapsed_time(Some(time::Duration::from_secs(5)))
        .build();
    retry(backoff, || {
        let query = query.clone();
        async move {
            match collector.collect(query, aggregation_parameter).await {
                Ok(collection) => Ok(collection),
                Err(janus_collector::Error::Http(error_response)) => {
                    if let Some(DapProblemType::InvalidBatchSize) =
                        error_response.dap_problem_type()
                    {
                        Err(backoff::Error::transient(janus_collector::Error::Http(
                            error_response,
                        )))
                    } else {
                        Err(backoff::Error::permanent(janus_collector::Error::Http(
                            error_response,
                        )))
                    }
                }
                Err(error) => Err(backoff::Error::permanent(error)),
            }
        }
    })
    .await
}

pub async fn submit_measurements_and_verify_aggregate_generic<V>(
    task_parameters: &TaskParameters,
    leader_port: u16,
    vdaf: V,
    test_case: &AggregationTestCase<V>,
    client_implementation: &ClientImplementation<V>,
) where
    V: vdaf::Client<16> + vdaf::Collector + InteropClientEncoding,
    V::AggregateResult: PartialEq,
{
    let before_timestamp =
        submit_measurements_generic(&test_case.measurements, client_implementation).await;

    verify_aggregate_generic(
        task_parameters,
        leader_port,
        vdaf,
        test_case,
        before_timestamp,
    )
    .await
}

pub async fn submit_measurements_generic<V>(
    measurements: &[V::Measurement],
    client_implementation: &ClientImplementation<V>,
) -> Time
where
    V: vdaf::Client<16> + vdaf::Collector + InteropClientEncoding,
    V::AggregateResult: PartialEq,
{
    // Submit some measurements, recording a timestamp before measurement upload to allow us to
    // determine the correct collect interval. (for time interval tasks)
    let time = RealClock::default().now();
    for measurement in measurements.iter() {
        client_implementation
            .upload(measurement, time)
            .await
            .unwrap();
    }

    time
}

pub async fn verify_aggregate_generic<V>(
    task_parameters: &TaskParameters,
    leader_port: u16,
    vdaf: V,
    test_case: &AggregationTestCase<V>,
    before_timestamp: Time,
) where
    V: vdaf::Client<16> + vdaf::Collector + InteropClientEncoding,
    V::AggregateResult: PartialEq,
{
    let (report_count, aggregate_result) = collect_aggregate_result_generic(
        task_parameters,
        leader_port,
        vdaf,
        before_timestamp,
        &test_case.aggregation_parameter,
    )
    .await;

    assert_eq!(
        report_count,
        u64::try_from(test_case.measurements.len()).unwrap()
    );
    assert_eq!(aggregate_result, test_case.aggregate_result);
}

pub async fn collect_aggregate_result_generic<V>(
    task_parameters: &TaskParameters,
    leader_port: u16,
    vdaf: V,
    before_timestamp: Time,
    aggregation_parameter: &V::AggregationParam,
) -> (u64, V::AggregateResult)
where
    V: vdaf::Client<16> + vdaf::Collector + InteropClientEncoding,
    V::AggregateResult: PartialEq,
{
    let leader_endpoint = task_parameters
        .endpoint_fragments
        .leader_endpoint_for_host(leader_port);
    let collector = Collector::builder(
        task_parameters.task_id,
        leader_endpoint,
        task_parameters.collector_auth_token.clone(),
        task_parameters.collector_hpke_keypair.clone(),
        vdaf,
    )
    .with_http_request_backoff(test_http_request_exponential_backoff())
    .with_collect_poll_backoff(
        ExponentialBackoffBuilder::new()
            .with_initial_interval(time::Duration::from_millis(500))
            .with_max_interval(task_parameters.collector_max_interval)
            .with_max_elapsed_time(Some(task_parameters.collector_max_elapsed_time))
            .build(),
    )
    .build()
    .unwrap();

    // Send a collect request and verify that we got the correct result.
    let (report_count, aggregate_result) = match &task_parameters.query_type {
        QueryType::TimeInterval => {
            let batch_interval = Interval::new(
                before_timestamp
                    .to_batch_interval_start(&task_parameters.time_precision)
                    .unwrap(),
                // Use two time precisions as the interval duration in order to avoid a race condition if
                // this test happens to run very close to the end of a batch window.
                Duration::from_seconds(2 * task_parameters.time_precision.as_seconds()),
            )
            .unwrap();

            let collection_1 = collect_generic(
                &collector,
                Query::new_time_interval(batch_interval),
                aggregation_parameter,
            )
            .await
            .unwrap();

            // Collect again to verify that collections can be repeated.
            let collection_2 = collect_generic(
                &collector,
                Query::new_time_interval(batch_interval),
                aggregation_parameter,
            )
            .await
            .unwrap();

            assert_eq!(collection_1.report_count(), collection_2.report_count());
            assert_eq!(
                collection_1.aggregate_result(),
                collection_2.aggregate_result()
            );

            (
                collection_2.report_count(),
                collection_2.aggregate_result().clone(),
            )
        }
        QueryType::FixedSize { .. } => {
            let mut requests = 0;
            let collection_1 = loop {
                requests += 1;
                let collection_res = collect_generic::<_, FixedSize>(
                    &collector,
                    Query::new_fixed_size(FixedSizeQuery::CurrentBatch),
                    aggregation_parameter,
                )
                .await;
                match collection_res {
                    Ok(collection) => break collection,
                    Err(e) => {
                        if requests >= 15 {
                            panic!(
                                "timed out waiting for a current batch query to succeed, error: \
                                 {e}"
                            );
                        }
                        sleep(StdDuration::from_secs(1)).await;
                        continue;
                    }
                }
            };

            let batch_id = *collection_1.partial_batch_selector().batch_id();

            // Collect again to verify that collections can be repeated.
            let collection_2 = collect_generic(
                &collector,
                Query::new_fixed_size(FixedSizeQuery::ByBatchId { batch_id }),
                aggregation_parameter,
            )
            .await
            .unwrap();

            assert_eq!(collection_1.report_count(), collection_2.report_count());
            assert_eq!(
                collection_1.aggregate_result(),
                collection_2.aggregate_result()
            );

            (
                collection_2.report_count(),
                collection_2.aggregate_result().clone(),
            )
        }
    };
    (report_count, aggregate_result)
}

pub async fn submit_measurements_and_verify_aggregate(
    test_name: &str,
    task_parameters: &TaskParameters,
    (leader_port, helper_port): (u16, u16),
    client_backend: &ClientBackend<'_>,
) {
    // We generate exactly one batch's worth of measurement uploads to work around an issue in
    // Daphne at time of writing.
    let total_measurements: usize = task_parameters.min_batch_size.try_into().unwrap();

    match &task_parameters.vdaf {
        VdafInstance::Prio3Count => {
            let vdaf = Prio3::new_count(2).unwrap();

            let num_true_measurements = total_measurements / 2;
            let num_false_measurements = total_measurements - num_true_measurements;
            assert!(num_true_measurements > 0 && num_false_measurements > 0);
            let measurements = iter::repeat(true)
                .take(num_true_measurements)
                .interleave(iter::repeat(false).take(num_false_measurements))
                .collect::<Vec<_>>();
            let test_case = AggregationTestCase {
                measurements,
                aggregation_parameter: (),
                aggregate_result: num_true_measurements.try_into().unwrap(),
            };

            let client_implementation = client_backend
                .build(
                    test_name,
                    task_parameters,
                    (leader_port, helper_port),
                    vdaf.clone(),
                )
                .await
                .unwrap();

            submit_measurements_and_verify_aggregate_generic(
                task_parameters,
                leader_port,
                vdaf,
                &test_case,
                &client_implementation,
            )
            .await;
        }
        VdafInstance::Prio3Sum { bits } => {
            let vdaf = Prio3::new_sum(2, *bits).unwrap();

            let measurements = iter::repeat_with(|| (random::<u128>()) >> (128 - bits))
                .take(total_measurements)
                .collect::<Vec<_>>();
            let aggregate_result = measurements.iter().sum();
            let test_case = AggregationTestCase {
                measurements,
                aggregation_parameter: (),
                aggregate_result,
            };

            let client_implementation = client_backend
                .build(
                    test_name,
                    task_parameters,
                    (leader_port, helper_port),
                    vdaf.clone(),
                )
                .await
                .unwrap();

            submit_measurements_and_verify_aggregate_generic(
                task_parameters,
                leader_port,
                vdaf,
                &test_case,
                &client_implementation,
            )
            .await;
        }
        VdafInstance::Prio3SumVec {
            bits,
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let vdaf = Prio3::new_sum_vec_multithreaded(2, *bits, *length, *chunk_length).unwrap();

            let measurements = iter::repeat_with(|| {
                iter::repeat_with(|| random::<u128>() >> (128 - bits))
                    .take(*length)
                    .collect::<Vec<_>>()
            })
            .take(total_measurements)
            .collect::<Vec<_>>();
            let aggregate_result =
                measurements
                    .iter()
                    .fold(vec![0u128; *length], |mut accumulator, measurement| {
                        for (sum, elem) in accumulator.iter_mut().zip(measurement.iter()) {
                            *sum += *elem;
                        }
                        accumulator
                    });
            let test_case = AggregationTestCase {
                measurements,
                aggregation_parameter: (),
                aggregate_result,
            };

            let client_implementation = client_backend
                .build(
                    test_name,
                    task_parameters,
                    (leader_port, helper_port),
                    vdaf.clone(),
                )
                .await
                .unwrap();

            submit_measurements_and_verify_aggregate_generic(
                task_parameters,
                leader_port,
                vdaf,
                &test_case,
                &client_implementation,
            )
            .await;
        }
        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs,
            bits,
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let vdaf = new_prio3_sum_vec_field64_multiproof_hmacsha256_aes128::<
                ParallelSumMultithreaded<_, _>,
            >(*proofs, *bits, *length, *chunk_length)
            .unwrap();

            let measurements = iter::repeat_with(|| {
                iter::repeat_with(|| random::<u64>() >> (64 - bits))
                    .take(*length)
                    .collect::<Vec<_>>()
            })
            .take(total_measurements)
            .collect::<Vec<_>>();
            let aggregate_result =
                measurements
                    .iter()
                    .fold(vec![0u64; *length], |mut accumulator, measurement| {
                        for (sum, elem) in accumulator.iter_mut().zip(measurement.iter()) {
                            *sum += *elem;
                        }
                        accumulator
                    });
            let test_case = AggregationTestCase {
                measurements,
                aggregation_parameter: (),
                aggregate_result,
            };

            let client_implementation = client_backend
                .build(
                    test_name,
                    task_parameters,
                    (leader_port, helper_port),
                    vdaf.clone(),
                )
                .await
                .unwrap();

            submit_measurements_and_verify_aggregate_generic(
                task_parameters,
                leader_port,
                vdaf,
                &test_case,
                &client_implementation,
            )
            .await;
        }
        VdafInstance::Prio3Histogram {
            length,
            chunk_length,
            dp_strategy: _,
        } => {
            let vdaf = Prio3::new_histogram_multithreaded(2, *length, *chunk_length).unwrap();

            let mut aggregate_result = vec![0; *length];
            let measurements = iter::repeat_with(|| {
                let choice = thread_rng().gen_range(0..*length);
                aggregate_result[choice] += 1;
                choice
            })
            .take(total_measurements)
            .collect::<Vec<_>>();
            let test_case = AggregationTestCase {
                measurements,
                aggregation_parameter: (),
                aggregate_result,
            };

            let client_implementation = client_backend
                .build(
                    test_name,
                    task_parameters,
                    (leader_port, helper_port),
                    vdaf.clone(),
                )
                .await
                .unwrap();

            submit_measurements_and_verify_aggregate_generic(
                task_parameters,
                leader_port,
                vdaf,
                &test_case,
                &client_implementation,
            )
            .await;
        }
        _ => panic!("Unsupported VdafInstance: {:?}", task_parameters.vdaf),
    }
}

pub async fn submit_measurements_and_verify_aggregate_varying_aggregation_parameter(
    test_name: &str,
    task_parameters: &TaskParameters,
    aggregation_parameters: &[dummy::AggregationParam],
    (leader_port, helper_port): (u16, u16),
    client_backend: &ClientBackend<'_>,
) {
    // We generate exactly one batch's worth of measurement uploads.
    let total_measurements: usize = task_parameters.min_batch_size.try_into().unwrap();

    match &task_parameters.vdaf {
        VdafInstance::Fake { rounds } => {
            let vdaf = dummy::Vdaf::new(*rounds);
            let client_implementation = client_backend
                .build(
                    test_name,
                    task_parameters,
                    (leader_port, helper_port),
                    vdaf.clone(),
                )
                .await
                .unwrap();

            let measurements = iter::repeat_with(random::<u8>)
                .take(total_measurements)
                .collect::<Vec<_>>();

            let before_timestamp =
                submit_measurements_generic(&measurements, &client_implementation).await;

            for aggregation_parameter in aggregation_parameters {
                let aggregate_result = measurements.iter().map(|m| u64::from(*m)).sum::<u64>()
                    % (u64::from(u8::MAX) + 1)
                    + u64::from(aggregation_parameter.0);

                let test_case = AggregationTestCase {
                    measurements: measurements.clone(),
                    aggregation_parameter: *aggregation_parameter,
                    aggregate_result,
                };

                verify_aggregate_generic(
                    task_parameters,
                    leader_port,
                    vdaf.clone(),
                    &test_case,
                    before_timestamp,
                )
                .await;
            }
        }
        _ => panic!("Unsupported VdafInstance: {:?}", task_parameters.vdaf),
    }
}
