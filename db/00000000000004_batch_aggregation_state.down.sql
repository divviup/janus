ALTER TABLE batch_aggregations ALTER COLUMN aggregate_share SET NOT NULL;
ALTER TABLE batch_aggregations DROP COLUMN state;

DROP TYPE BATCH_AGGREGATION_STATE;
