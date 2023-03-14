//! Implements functionality for computing & validating aggregate shares.

use super::Error;
use janus_aggregator_core::{datastore::models::BatchAggregation, task::Task};
use janus_core::report_id::ReportIdChecksumExt;
use janus_messages::{query_type::QueryType, ReportIdChecksum};
use prio::vdaf::{self, Aggregatable};

/// Computes the aggregate share over the provided batch aggregations.
/// The assumption is that all aggregation jobs contributing to those batch aggregations have
/// been driven to completion, and that the query count requirements have been validated for the
/// included batches.
#[tracing::instrument(skip(task), fields(task_id = ?task.id()), err)]
pub(crate) async fn compute_aggregate_share<
    const SEED_SIZE: usize,
    Q: QueryType,
    A: vdaf::Aggregator<SEED_SIZE, 16>,
>(
    task: &Task,
    batch_aggregations: &[BatchAggregation<SEED_SIZE, Q, A>],
) -> Result<(A::AggregateShare, u64, ReportIdChecksum), Error> {
    // At the moment we construct an aggregate share (either handling AggregateShareReq in the
    // helper or driving a collection job in the leader), there could be some incomplete aggregation
    // jobs whose results not been accumulated into the batch aggregations we just queried from the
    // datastore, meaning we will aggregate over an incomplete view of data, which:
    //
    //  * reduces fidelity of the resulting aggregates,
    //  * could cause us to fail to meet the minimum batch size for the task,
    //  * or for particularly pathological timing, could cause us to aggregate a different set of
    //    reports than the leader did (though the checksum will detect this).
    //
    // There's not much the helper can do about this, because an aggregate job might be unfinished
    // because it's waiting on an aggregate sub-protocol message that is never coming because the
    // leader has abandoned that job. Thus the helper has no choice but to assume that any
    // unfinished aggregation jobs were intentionally abandoned by the leader (see issue #104 for
    // more discussion).
    //
    // On the leader side, we know/assume that we would not be stepping a collection job unless we had
    // verified that the constituent aggregation jobs were finished.
    //
    // In either case, we go ahead and service the aggregate share request with whatever batch
    // aggregations are available now.
    let mut total_report_count = 0;
    let mut total_checksum = ReportIdChecksum::default();
    let mut total_aggregate_share: Option<A::AggregateShare> = None;

    for batch_aggregation in batch_aggregations {
        // XOR this batch interval's checksum into the overall checksum
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.2
        total_checksum = total_checksum.combined_with(batch_aggregation.checksum());

        // Sum all the report counts
        // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.2
        total_report_count += batch_aggregation.report_count();

        match &mut total_aggregate_share {
            Some(share) => share.merge(batch_aggregation.aggregate_share())?,
            None => total_aggregate_share = Some(batch_aggregation.aggregate_share().clone()),
        }
    }

    // Only happens if there were no batch aggregations, which would get caught by the
    // min_batch_size check below, but we have to unwrap the option.
    let total_aggregate_share = total_aggregate_share
        .ok_or_else(|| Error::InvalidBatchSize(*task.id(), total_report_count))?;

    // Validate batch size per
    // https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.5.6
    if !task.validate_batch_size(total_report_count) {
        return Err(Error::InvalidBatchSize(*task.id(), total_report_count));
    }

    Ok((total_aggregate_share, total_report_count, total_checksum))
}
