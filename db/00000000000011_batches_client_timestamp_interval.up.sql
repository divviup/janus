ALTER TABLE batches ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;
ALTER TABLE aggregate_share_jobs ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;