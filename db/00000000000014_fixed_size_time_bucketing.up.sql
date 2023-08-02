ALTER TABLE outstanding_batches ADD COLUMN time_bucket_start TIMESTAMP;
CREATE INDEX outstanding_batches_task_and_time_bucket_index ON outstanding_batches (task_id, time_bucket_start);
DROP INDEX client_reports_task_unaggregated CASCADE;
CREATE INDEX client_reports_task_and_timestamp_unaggregated_index ON client_reports (task_id, client_timestamp) WHERE aggregation_started = FALSE;
