-- We create a new state for batch_aggregations.
-- AggregateShare is now optional (if there are no reports), so we drop the NOT NULL constraint.

CREATE TYPE BATCH_AGGREGATION_STATE AS ENUM(
    'AGGREGATING',  -- this batch aggregation has not been collected & permits further aggregation
    'COLLECTED'     -- this batch aggregation has been collected & no longer permits aggregation
);

ALTER TABLE batch_aggregations ADD COLUMN state BATCH_AGGREGATION_STATE NOT NULL;  -- the current state of this batch aggregation
ALTER TABLE batch_aggregations ALTER COLUMN aggregate_share DROP NOT NULL;
