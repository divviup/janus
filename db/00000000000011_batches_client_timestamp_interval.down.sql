ALTER TABLE batches DROP COLUMN client_timestamp_interval;
ALTER TABLE batch_aggregations ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;
