use janus_aggregator_core::task::{AggregationMode, BatchMode, test_util::TaskBuilder};
use janus_core::{
    test_util::install_test_trace_subscriber,
    vdaf::{VdafInstance, vdaf_dp_strategies},
};
use janus_integration_tests::client::ClientBackend;
use opentelemetry_sdk::metrics::data::Histogram;

use crate::{
    common::submit_measurements_and_verify_aggregate, initialize_rustls, janus::JanusInProcessPair,
};

#[tokio::test(flavor = "multi_thread")]
async fn janus_metrics_count() {
    run_metrics_test(VdafInstance::Prio3Count, "Prio3Count", 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_metrics_sum() {
    run_metrics_test(
        VdafInstance::Prio3Sum {
            max_measurement: 10,
        },
        "Prio3Sum",
        4,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_metrics_sumvec() {
    run_metrics_test(
        VdafInstance::Prio3SumVec {
            max_measurement: 250,
            length: 3,
            chunk_length: 5,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
        },
        "Prio3SumVec",
        24,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_metrics_sumvec_custom() {
    run_metrics_test(
        VdafInstance::Prio3SumVecField64MultiproofHmacSha256Aes128 {
            proofs: 2,
            max_measurement: 250,
            length: 3,
            chunk_length: 5,
            dp_strategy: vdaf_dp_strategies::Prio3SumVec::NoDifferentialPrivacy,
        },
        "Prio3SumVecField64MultiproofHmacSha256Aes128",
        24,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn janus_metrics_histogram() {
    run_metrics_test(
        VdafInstance::Prio3Histogram {
            length: 13,
            chunk_length: 4,
            dp_strategy: vdaf_dp_strategies::Prio3Histogram::NoDifferentialPrivacy,
        },
        "Prio3Histogram",
        13,
    )
    .await;
}

async fn run_metrics_test(vdaf: VdafInstance, vdaf_name: &str, dimension: u64) {
    install_test_trace_subscriber();
    initialize_rustls();

    let janus_pair = JanusInProcessPair::new(TaskBuilder::new(
        BatchMode::LeaderSelected {
            batch_time_window_size: None,
        },
        AggregationMode::Synchronous,
        vdaf,
    ))
    .await;

    submit_measurements_and_verify_aggregate(
        &format!("metrics_{vdaf_name}"),
        &janus_pair.task_parameters,
        (janus_pair.leader.port(), janus_pair.helper.port()),
        &ClientBackend::InProcess,
    )
    .await;

    for (metrics, aggregator) in [
        (&janus_pair.leader.aggregation_job_driver_metrics, "leader"),
        (&janus_pair.helper.aggregator_metrics, "helper"),
    ] {
        let export = metrics.collect().await;
        let dimension_histogram_metric = &export["janus_aggregated_report_share_vdaf_dimension"];
        let dimension_histogram_data = dimension_histogram_metric
            .data
            .as_any()
            .downcast_ref::<Histogram<u64>>()
            .expect(aggregator);
        let dimension_data_point = dimension_histogram_data
            .data_points
            .iter()
            .find(|data_point| data_point.count > 0)
            .expect(aggregator);
        let vdaf_type_kv = dimension_data_point
            .attributes
            .iter()
            .find(|kv| kv.key.as_str() == "type")
            .expect(aggregator);
        assert_eq!(vdaf_type_kv.value.as_str(), vdaf_name, "{aggregator}");
        let average_dimension = dimension_data_point.sum / dimension_data_point.count;
        assert_eq!(average_dimension, dimension, "{aggregator}");
    }
}
