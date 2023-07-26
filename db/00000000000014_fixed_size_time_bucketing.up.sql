ALTER TABLE outstanding_batches ADD COLUMN time_bucket_start TIMESTAMP;
CREATE INDEX outstanding_batches_task_and_time_bucket_index ON outstanding_batches (task_id, time_bucket_start);
