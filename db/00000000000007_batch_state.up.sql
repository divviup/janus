-- Specifies the possible state of aggregation for a given batch.
CREATE TYPE BATCH_STATE AS ENUM(
    'OPEN',     -- this batch can accept additional aggregation jobs.
    'CLOSING',  -- this batch can accept additional aggregation jobs, but will transition to CLOSED when there are no outstanding aggregation jobs.
    'CLOSED'    -- this batch can no longer accept additional aggregation jobs.
);

-- Tracks the state of a given batch, by aggregation parameter. Populated for the Leader only.
CREATE TABLE batches(
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id                       BIGINT NOT NULL,       -- the task ID
    batch_identifier              BYTEA NOT NULL,        -- encoded query-type-specific batch identifier (corresponds to identifier in BatchSelector)
    aggregation_param             BYTEA NOT NULL,        -- the aggregation parameter (opaque VDAF message)
    state                         BATCH_STATE NOT NULL,  -- the state of aggregations for this batch
    outstanding_aggregation_jobs  BIGINT NOT NULL,       -- the number of outstanding aggregation jobs

    CONSTRAINT batches_unique_id UNIQUE(task_id, batch_identifier, aggregation_param),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

ALTER TYPE COLLECTION_JOB_STATE ADD VALUE 'COLLECTABLE';
