ALTER TABLE batches ADD COLUMN batch_interval TSRANGE;  -- batch interval, as a TSRANGE, populated only for time-interval tasks. (will always match batch_identifier)
ALTER TABLE batches ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;  -- the minimal interval containing all of client timestamps included in this batch
ALTER TABLE aggregate_share_jobs ADD COLUMN client_timestamp_interval TSRANGE NOT NULL;  -- the minimal interval containing all of client timestamps included in this aggregate share job
