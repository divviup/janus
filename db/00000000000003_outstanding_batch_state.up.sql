-- Specifies the possible state of an outstanding batch.
CREATE TYPE OUTSTANDING_BATCH_STATE AS ENUM(
    'FILLING',  -- this outstanding batch is still being considered for additional reports
    'FILLED'    -- this outstanding batch has received enough reports, no more are necessary
);
ALTER TABLE outstanding_batches ADD COLUMN state OUTSTANDING_BATCH_STATE NOT NULL DEFAULT 'FILLING';
CREATE INDEX outstanding_batches_task_id_and_time_bucket_start ON outstanding_batches(task_id, time_bucket_start) WHERE state = 'FILLING';
DROP INDEX outstanding_batches_task_and_time_bucket_index CASCADE;
