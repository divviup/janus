use backoff::{future::retry, ExponentialBackoffBuilder};
use itertools::Itertools;
use janus_aggregator_core::task::{test_util::TaskBuilder, QueryType};
use janus_collector::{Collection, Collector};
use janus_core::{
    retries::test_http_request_exponential_backoff,
    time::{Clock, RealClock, TimeExt},
    vdaf::VdafInstance,
};
use janus_integration_tests::{
    client::{ClientBackend, ClientImplementation, InteropClientEncoding},
    AggregatorEndpointFragments, EndpointFragments, TaskParameters,
};
use janus_messages::{
    problem_type::DapProblemType,
    query_type::{self, FixedSize},
    Duration, FixedSizeQuery, Interval, Query,
};
use prio::vdaf::{self, prio3::Prio3};
use rand::{random, thread_rng, Rng};
use std::{iter, time::Duration as StdDuration};
use tokio::time::{self, sleep};
use url::Url;

/// Returns a tuple of [`TaskParameters`] and a task builder. This is suitable for test aggregators
/// running in virtual networks (a Docker network or a Kind cluster).
pub fn test_task_builder(
    vdaf: VdafInstance,
    query_type: QueryType,
) -> (TaskParameters, TaskBuilder) {
    let endpoint_random_value = hex::encode(random::<[u8; 4]>());
    let endpoint_fragments = EndpointFragments {
        leader: AggregatorEndpointFragments::VirtualNetwork {
            host: format!("leader-{endpoint_random_value}"),
            path: "/".to_string(),
        },
        helper: AggregatorEndpointFragments::VirtualNetwork {
            host: format!("helper-{endpoint_random_value}"),
            path: "/".to_string(),
        },
    };
    let task_builder = TaskBuilder::new(query_type, vdaf.clone())
        .with_leader_aggregator_endpoint(
            Url::parse(&format!("http://leader-{endpoint_random_value}:8080/")).unwrap(),
        )
        .with_helper_aggregator_endpoint(
            Url::parse(&format!("http://helper-{endpoint_random_value}:8080/")).unwrap(),
        )
        .with_min_batch_size(46)
        // Force use of DAP-Auth-Tokens, as required by interop testing standard.
        .with_dap_auth_aggregator_token()
        .with_dap_auth_collector_token();
    let task_parameters = TaskParameters {
        task_id: *task_builder.task_id(),
        endpoint_fragments,
        query_type,
        vdaf,
        min_batch_size: task_builder.min_batch_size(),
        time_precision: *task_builder.time_precision(),
        collector_hpke_keypair: task_builder.collector_hpke_keypair().clone(),
        collector_auth_token: task_builder.collector_auth_token().clone(),
    };

    (task_parameters, task_builder)
}

/// Returns a tuple of [`TaskParameters`] and a task builder. This is suitable for test aggregators
/// running on the host. Note that the task builder must be updated with the helper's endpoint
/// before passing task parameters to the leader.
#[allow(unused)]
pub fn test_task_builder_host(
    vdaf: VdafInstance,
    query_type: QueryType,
) -> (TaskParameters, TaskBuilder) {
    let endpoint_fragments = EndpointFragments {
        leader: AggregatorEndpointFragments::Localhost {
            path: "/".to_string(),
        },
        helper: AggregatorEndpointFragments::Localhost {
            path: "/".to_string(),
        },
    };
    let task_builder = TaskBuilder::new(query_type, vdaf.clone())
        .with_leader_aggregator_endpoint(Url::parse("http://invalid/").unwrap())
        .with_helper_aggregator_endpoint(Url::parse("http://invalid/").unwrap())
        .with_min_batch_size(46)
        .with_dap_auth_aggregator_token()
        .with_dap_auth_collector_token();
    let task_parameters = TaskParameters {
        task_id: *task_builder.task_id(),
        endpoint_fragments,
        query_type,
        vdaf,
        min_batch_size: task_builder.min_batch_size(),
        time_precision: *task_builder.time_precision(),
        collector_hpke_keypair: task_builder.collector_hpke_keypair().clone(),
        collector_auth_token: task_builder.collector_auth_token().clone(),
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
    client_implementation: &ClientImplementation<'_, V>,
) where
    V: vdaf::Client<16> + vdaf::Collector + InteropClientEncoding,
    V::AggregateResult: PartialEq,
{
    // Submit some measurements, recording a timestamp before measurement upload to allow us to
    // determine the correct collect interval. (for time interval tasks)
    let before_timestamp = RealClock::default().now();
    for measurement in test_case.measurements.iter() {
        client_implementation.upload(measurement).await.unwrap();
    }

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
            .with_max_interval(time::Duration::from_millis(500))
            .with_max_elapsed_time(Some(time::Duration::from_secs(60)))
            .build(),
    )
    .build()
    .unwrap();

    // Send a collect request and verify that we got the correct result.
    match &task_parameters.query_type {
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
            let collection = collect_generic(
                &collector,
                Query::new_time_interval(batch_interval),
                &test_case.aggregation_parameter,
            )
            .await
            .unwrap();

            assert_eq!(
                collection.report_count(),
                u64::try_from(test_case.measurements.len()).unwrap()
            );
            assert_eq!(collection.aggregate_result(), &test_case.aggregate_result);
        }
        QueryType::FixedSize { .. } => {
            let mut requests = 0;
            let collection = loop {
                requests += 1;
                let collection_res = collect_generic::<_, FixedSize>(
                    &collector,
                    Query::new_fixed_size(FixedSizeQuery::CurrentBatch),
                    &test_case.aggregation_parameter,
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

            assert_eq!(
                collection.report_count(),
                u64::try_from(test_case.measurements.len()).unwrap()
            );
            assert_eq!(collection.aggregate_result(), &test_case.aggregate_result);
        }
    };
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

            let num_nonzero_measurements = total_measurements / 2;
            let num_zero_measurements = total_measurements - num_nonzero_measurements;
            assert!(num_nonzero_measurements > 0 && num_zero_measurements > 0);
            let measurements = iter::repeat(1)
                .take(num_nonzero_measurements)
                .interleave(iter::repeat(0).take(num_zero_measurements))
                .collect::<Vec<_>>();
            let test_case = AggregationTestCase {
                measurements,
                aggregation_parameter: (),
                aggregate_result: num_nonzero_measurements.try_into().unwrap(),
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
        } => {
            let vdaf = Prio3::new_sum_vec_multithreaded(2, *bits, *length, *chunk_length).unwrap();

            let measurements = iter::repeat_with(|| {
                iter::repeat_with(|| (random::<u128>()) >> (128 - bits))
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
        VdafInstance::Prio3Histogram {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_histogram(2, *length, *chunk_length).unwrap();

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
        VdafInstance::Prio3CountVec {
            length,
            chunk_length,
        } => {
            let vdaf = Prio3::new_sum_vec_multithreaded(2, 1, *length, *chunk_length).unwrap();

            let measurements = iter::repeat_with(|| {
                iter::repeat_with(|| random::<bool>() as u128)
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
        _ => panic!("Unsupported VdafInstance: {:?}", task_parameters.vdaf),
    }
}
