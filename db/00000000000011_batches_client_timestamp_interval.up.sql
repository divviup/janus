ALTER TABLE batch_aggregations DROP COLUMN client_timestamp_interval;
ALTER TABLE batches ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;
