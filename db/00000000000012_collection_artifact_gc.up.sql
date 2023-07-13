ALTER TABLE batch_aggregations ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;
ALTER TABLE batches ADD COLUMN batch_interval TSRANGE;
