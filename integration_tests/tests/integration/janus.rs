use crate::{
    common::{
        build_test_task, collect_aggregate_result_generic,
        submit_measurements_and_verify_aggregate,
        submit_measurements_and_verify_aggregate_varying_aggregation_parameter,
        submit_measurements_generic, TestContext,
    },
    initialize_rustls,
};
use janus_aggregator_core::task::{test_util::TaskBuilder, QueryType};
use janus_core::{
    test_util::install_test_trace_subscriber,
    vdaf::{vdaf_dp_strategies, VdafInstance},
};
#[cfg(feature = "testcontainer")]
use janus_integration_tests::janus::JanusContainer;
use janus_integration_tests::{client::ClientBackend, janus::JanusInProcess, TaskParameters};
#[cfg(feature = "testcontainer")]
use janus_interop_binaries::test_util::generate_network_name;
use janus_messages::Role;
use prio::{
    dp::{
        distributions::PureDpDiscreteLaplace, DifferentialPrivacyStrategy, PureDpBudget, Rational,
    },
    field::{Field128, FieldElementWithInteger},
    vdaf::{dummy, prio3::Prio3},
};
use std::{iter, time::Duration};

/// A pair of Janus instances, running in containers, against which integration tests may be run.
#[cfg(feature = "testcontainer")]
struct JanusContainerPair {
    /// Task parameters needed by the client and collector, for the task configured in both Janus
    /// aggregators.
    task_parameters: TaskParameters,

    /// Handle to the leader's resources, which are released on drop.
    leader: JanusContainer,
    /// Handle to the helper's resources, which are released on drop.
    helper: JanusContainer,
}

#[cfg(feature = "testcontainer")]
impl JanusContainerPair {
    /// Set up a new pair of containerized Janus test instances, and set up a new task in each using
    /// the given VDAF and query type.
    pub async fn new(
        test_name: &str,
        vdaf: VdafInstance,
        query_type: QueryType,
    ) -> JanusContainerPair {
        let (task_parameters, task_builder) = build_test_task(
            TaskBuilder::new(query_type, vdaf),
            TestContext::VirtualNetwork,
            Duration::from_millis(500),
            Duration::from_secs(60),
        );
        let task = task_builder.build();

        let network = generate_network_name();
        let leader = JanusContainer::new(test_name, &network, &task, Role::Leader).await;
        let helper = JanusContainer::new(test_name, &network, &task, Role::Helper).await;

        Self {
            task_parameters,
            leader,
            helper,
        }
    }
}

/// A pair of Janus instances, running in-process, against which integration tests may be run.
struct JanusInProcessPair {
    /// Task parameters needed by the client and collector, for the task configured in both Janus
    /// aggregators.
    task_parameters: TaskParameters,

    /// The leader's resources, which are released on drop.
    leader: JanusInProcess,
    /// The helper's resources, which are released on drop.
    helper: JanusInProcess,
}

impl JanusInProcessPair {
    /// Set up a new pair of in-process Janus test instances, and set up a new task in each using
    /// the given VDAF and query type.
    pub async fn new(task_builder: TaskBuilder) -> JanusInProcessPair {
        let (task_parameters, mut task_builder) = build_test_task(
            task_builder,
            TestContext::Host,
            Duration::from_millis(500),
            Duration::from_secs(60),
        );

        let helper = JanusInProcess::new(&task_builder.clone().build(), Role::Helper).await;
        let helper_url = task_parameters
            .endpoint_fragments
            .helper
            .endpoint_for_host(helper.port());
        task_builder = task_builder.with_helper_aggregator_endpoint(helper_url);
        let leader = JanusInProcess::new(&task_builder.build(), Role::Leader).await;

        Self {
            task_parameters,
            leader,
            helper,
        }
    }
}

/// This test exercises Prio3Count with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "testcontainer")]
async fn janus_janus_count() {
    static TEST_NAME: &str = "janus_janus_count";
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair =
        JanusContainerPair::new(TEST_NAME, VdafInstance::Prio3Count, QueryType::TimeInterval).await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        TEST_NAME,
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3Count with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_count() {
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3Count,
    ))
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "janus_in_process_count",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3Sum with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "testcontainer")]
async fn janus_janus_sum_16() {
    static TEST_NAME: &str = "janus_janus_sum_16";
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusContainerPair::new(
        TEST_NAME,
        VdafInstance::Prio3Sum { bits: 16 },
        QueryType::TimeInterval,
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        TEST_NAME,
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3Sum with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_sum_16() {
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3Sum { bits: 16 },
    ))
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "janus_in_process_sum_16",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3Histogram with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "testcontainer")]
async fn janus_janus_histogram_4_buckets() {
    static TEST_NAME: &str = "janus_janus_histogram_4_buckets";
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusContainerPair::new(
        TEST_NAME,
        VdafInstance::Prio3Histogram {
            length: 4,
            chunk_length: 2,
            dp_strategy: vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy,
        },
        QueryType::TimeInterval,
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        TEST_NAME,
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3Histogram with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_histogram_4_buckets() {
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3Histogram {
            length: 4,
            chunk_length: 2,
            dp_strategy: vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy,
        },
    ))
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "janus_in_process_histogram_4_buckets",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises the fixed-size query type with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "testcontainer")]
async fn janus_janus_fixed_size() {
    static TEST_NAME: &str = "janus_janus_fixed_size";
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusContainerPair::new(
        TEST_NAME,
        VdafInstance::Prio3Count,
        QueryType::FixedSize {
            max_batch_size: Some(50),
            batch_time_window_size: None,
        },
    )
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        TEST_NAME,
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises the fixed-size query type with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_fixed_size() {
    install_test_trace_subscriber();
    initialize_rustls();

    // Start servers.
    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::FixedSize {
            max_batch_size: Some(50),
            batch_time_window_size: None,
        },
        VdafInstance::Prio3Count,
    ))
    .await;

    // Run the behavioral test.
    submit_measurements_and_verify_aggregate(
        "janus_in_process_fixed_size",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3SumVec with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
#[cfg(feature = "testcontainer")]
async fn janus_janus_sum_vec() {
    static TEST_NAME: &str = "janus_janus_sum_vec";
    install_test_trace_subscriber();
    initialize_rustls();

    let janus_pair = JanusContainerPair::new(
        TEST_NAME,
        VdafInstance::Prio3SumVec {
            bits: 16,
            length: 15,
            chunk_length: 16,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
        },
        QueryType::TimeInterval,
    )
    .await;

    submit_measurements_and_verify_aggregate(
        TEST_NAME,
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3SumVec with Janus as both the leader and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_sum_vec() {
    install_test_trace_subscriber();
    initialize_rustls();

    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3SumVec {
            bits: 16,
            length: 15,
            chunk_length: 16,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
        },
    ))
    .await;

    submit_measurements_and_verify_aggregate(
        "janus_in_process_sum_vec",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises Prio3SumVecField64MultiproofHmacSha256Aes128 with Janus as both the leader
/// and the helper.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_customized_sum_vec() {
    install_test_trace_subscriber();
    initialize_rustls();

    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs: 2,
            bits: 16,
            length: 15,
            chunk_length: 16,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
        },
    ))
    .await;

    submit_measurements_and_verify_aggregate(
        "janus_in_process_customized_sum_vec",
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises a 1-round VDAF with an aggregation parameter.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "fixed size with agg param not yet supported (#225)"]
async fn janus_in_process_one_round_with_agg_param_fixed_size() {
    install_test_trace_subscriber();
    initialize_rustls();

    let janus_pair = JanusInProcessPair::new(
        TaskBuilder::new(
            QueryType::FixedSize {
                max_batch_size: Some(50),
                batch_time_window_size: None,
            },
            VdafInstance::Fake { rounds: 1 },
        )
        .with_max_batch_query_count(3),
    )
    .await;

    submit_measurements_and_verify_aggregate_varying_aggregation_parameter(
        "janus_in_process_one_round_with_agg_param_fixed_size",
        &janus_pair.task_parameters,
        &[
            dummy::AggregationParam(10),
            // TODO(#225): Querying a single batch multiple times doesn't work yet, failing with
            // "invalid number of reports (0)"
            // dummy::AggregationParam(11),
            // dummy::AggregationParam(12),
        ],
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

/// This test exercises a 1-round VDAF with an aggregation parameter.
#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_one_round_with_agg_param_time_interval() {
    install_test_trace_subscriber();
    initialize_rustls();

    let janus_pair = JanusInProcessPair::new(
        TaskBuilder::new(QueryType::TimeInterval, VdafInstance::Fake { rounds: 1 })
            .with_max_batch_query_count(3),
    )
    .await;

    submit_measurements_and_verify_aggregate_varying_aggregation_parameter(
        "janus_in_process_one_round_with_agg_param_time_interval",
        &janus_pair.task_parameters,
        &[
            dummy::AggregationParam(10),
            // TODO(#225): Querying a single batch multiple times doesn't work yet, failing with
            // "invalid number of reports (0)"
            // dummy::AggregationParam(11),
            // dummy::AggregationParam(12),
        ],
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_histogram_dp_noise() {
    static TEST_NAME: &str = "janus_in_process_histogram_dp_noise";
    const HISTOGRAM_LENGTH: usize = 100;
    const CHUNK_LENGTH: usize = 10;

    install_test_trace_subscriber();
    initialize_rustls();

    let epsilon = Rational::from_unsigned(1u128, 10u128).unwrap();
    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3Histogram {
            length: HISTOGRAM_LENGTH,
            chunk_length: CHUNK_LENGTH,
            dp_strategy: vdaf_dp_strategies::Prio3Histogram::PureDpDiscreteLaplace(
                PureDpDiscreteLaplace::from_budget(PureDpBudget::new(epsilon).unwrap()),
            ),
        },
    ))
    .await;
    let vdaf = Prio3::new_histogram_multithreaded(2, HISTOGRAM_LENGTH, CHUNK_LENGTH).unwrap();

    let total_measurements: usize = janus_pair
        .task_parameters
        .min_batch_size
        .try_into()
        .unwrap();
    let measurements = iter::repeat(0).take(total_measurements).collect::<Vec<_>>();
    let client_implementation = ClientBackend::InProcess
        .build(
            TEST_NAME,
            &janus_pair.task_parameters,
            (janus_pair.leader.port(), janus_pair.helper.port()),
            vdaf.clone(),
        )
        .await
        .unwrap();
    let before_timestamp = submit_measurements_generic(&measurements, &client_implementation).await;
    let (report_count, aggregate_result) = collect_aggregate_result_generic(
        &janus_pair.task_parameters,
        janus_pair.leader.port(),
        vdaf,
        before_timestamp,
        &(),
    )
    .await;
    assert_eq!(report_count, janus_pair.task_parameters.min_batch_size);

    let mut un_noised_result = [0u128; HISTOGRAM_LENGTH];
    un_noised_result[0] = report_count.into();
    // Smoke test: Just confirm that some noise was added. Since epsilon is small, the noise will be
    // large (drawn from Laplace_Z(20) + Laplace_Z(20)), and it is highly unlikely that all 100
    // noise values will be zero simultaneously.
    assert_ne!(aggregate_result, un_noised_result);

    assert!(aggregate_result
        .iter()
        .all(|x| *x < Field128::modulus() / 4 || *x > Field128::modulus() / 4 * 3));
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_in_process_sumvec_dp_noise() {
    static TEST_NAME: &str = "janus_in_process_sumvec_dp_noise";
    const VECTOR_LENGTH: usize = 50;
    const BITS: usize = 2;
    const CHUNK_LENGTH: usize = 10;

    install_test_trace_subscriber();
    initialize_rustls();

    let epsilon = Rational::from_unsigned(1u128, 10u128).unwrap();
    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        QueryType::TimeInterval,
        VdafInstance::Prio3SumVec {
            bits: BITS,
            length: VECTOR_LENGTH,
            chunk_length: CHUNK_LENGTH,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::PureDpDiscreteLaplace(
                PureDpDiscreteLaplace::from_budget(PureDpBudget::new(epsilon).unwrap()),
            ),
        },
    ))
    .await;
    let vdaf = Prio3::new_sum_vec_multithreaded(2, BITS, VECTOR_LENGTH, CHUNK_LENGTH).unwrap();

    let total_measurements: usize = janus_pair
        .task_parameters
        .min_batch_size
        .try_into()
        .unwrap();
    let measurements = iter::repeat(vec![0; VECTOR_LENGTH])
        .take(total_measurements)
        .collect::<Vec<_>>();
    let client_implementation = ClientBackend::InProcess
        .build(
            TEST_NAME,
            &janus_pair.task_parameters,
            (janus_pair.leader.port(), janus_pair.helper.port()),
            vdaf.clone(),
        )
        .await
        .unwrap();
    let before_timestamp = submit_measurements_generic(&measurements, &client_implementation).await;
    let (report_count, aggregate_result) = collect_aggregate_result_generic(
        &janus_pair.task_parameters,
        janus_pair.leader.port(),
        vdaf,
        before_timestamp,
        &(),
    )
    .await;
    assert_eq!(report_count, janus_pair.task_parameters.min_batch_size);

    let un_noised_result = [0u128; VECTOR_LENGTH];
    // Smoke test: Just confirm that some noise was added. Since epsilon is small, the noise will be
    // large (drawn from Laplace_Z(150) + Laplace_Z(150)), and it is highly unlikely that all 50
    // noise values will be zero simultaneously.
    assert_ne!(aggregate_result, un_noised_result);

    assert!(aggregate_result
        .iter()
        .all(|x| *x < Field128::modulus() / 4 || *x > Field128::modulus() / 4 * 3));
}
