-- TODO(brandon): check if deployed version of PostgreSQL has gen_random_uuid built in and remove pgcrypto extension if so
CREATE EXTENSION pgcrypto; -- for gen_random_uuid()

-- Identifies a particular VDAF.
CREATE TYPE VDAF_IDENTIFIER AS ENUM(
    'PRIO3',
    'POPLAR1'
);

-- Corresponds to a PPM task, containing static data associated with the task.
CREATE TABLE tasks(
    id                     BYTEA PRIMARY KEY,         -- 32-byte TaskID as defined by the PPM specification
    ord                    BIGINT NOT NULL,           -- the order of this aggregator for this task; 0 is leader, 1 or larger is helper
    aggregator_endpoints   TEXT[] NOT NULL,           -- aggregator HTTPS endpoints, leader first
    vdaf                   VDAF_IDENTIFIER NOT NULL,  -- the VDAF in use for this task
    vdaf_verify_param      BYTEA NOT NULL,            -- the VDAF verify parameter (opaque message)
    max_batch_lifetime     BIGINT NOT NULL,           -- the maximum number of times a given batch may be collected
    min_batch_size         BIGINT NOT NULL,           -- the minimum number of reports in a batch to allow it to be collected
    min_batch_duration     INTERVAL NOT NULL,         -- the duration of a single batch window
    collector_hpke_config  BYTEA NOT NULL             -- the HPKE config of the helper (encoded HpkeConfig message)

    -- TODO(brandon): include agg_auth_key if we decide it shouldn't go in a secret store
);

-- Individual reports received from clients.
CREATE TABLE client_reports(
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    task_id       BYTEA NOT NULL,      -- task ID the report is associated with
    nonce_time    TIMESTAMP NOT NULL,  -- timestamp from nonce
    nonce_rand    BIGINT NOT NULL,     -- random value from nonce
    extensions    BYTEA NOT NULL,      -- sequence of encoded Extension messages
    input_shares  BYTEA[] NOT NULL,    -- array of encoded HpkeCiphertext messages

    CONSTRAINT unique_task_id_and_nonce UNIQUE(task_id, nonce_time, nonce_rand),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
CREATE INDEX client_reports_task_and_time_index ON client_reports(task_id, nonce_time);

-- Specifies the possible state of an aggregation job.
CREATE TYPE AGGREGATION_JOB_STATE AS ENUM(
    'IN_PROGRESS', -- at least one included preparation is in a non-terminal (WAITING) state
    'FINISHED'     -- all client reports have reached a terminal state (FINISHED, FAILED, INVALID)
);

-- An aggregation job, representing the aggregation of a number of client reports.
CREATE TABLE aggregation_jobs(
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    task_id            BYTEA NOT NULL,                  -- task
    aggregation_param  BYTEA NOT NULL,                  -- encoded aggregation parameter (opaque VDAF message)
    state              AGGREGATION_JOB_STATE NOT NULL,  -- current state of the aggregation job

    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- An aggregation attempt for a single client report. An aggregation job logically contains a number
-- of report aggregations. A single client report might be aggregated in multiple aggregation jobs &
-- therefore have multiple associated report aggregations.
CREATE TABLE report_aggregations(
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    aggregation_job_id  BIGINT NOT NULL,  -- the aggregation job ID this report aggregation is associated with
    client_report_id    BIGINT NOT NULL,  -- the client report ID this report aggregation is associated with
    ord                 BIGINT NOT NULL,  -- a value used to specify the ordering of client reports in the aggregation job
    transition          BYTEA NOT NULL,   -- encoded Transition message, representing the current preparation state of this report in this aggregation job

    CONSTRAINT unique_ord UNIQUE(aggregation_job_id, ord),
    CONSTRAINT fk_aggregation_job_id FOREIGN KEY(aggregation_job_id) REFERENCES aggregation_jobs(id),
    CONSTRAINT fk_client_report_id FOREIGN KEY(client_report_id) REFERENCES client_reports(id)
);
CREATE INDEX report_aggregations_aggregation_job_id_index ON report_aggregations(aggregation_job_id);

-- Information on incremental aggregation, for VDAFs that support incremental aggregation (eg prio3).
CREATE TABLE batch_window_aggregations(
    task_id             BYTEA NOT NULL,      -- the task ID
    batch_window_start  TIMESTAMP NOT NULL,  -- the start of the batch window
    aggregate_share     BYTEA NOT NULL,      -- the (incremental) aggregate share
    report_count        BIGINT NOT NULL,     -- the (incremental) client report count
    checksum            BYTEA NOT NULL,      -- the (incremental) checksum

    PRIMARY KEY(task_id, batch_window_start)

    -- TODO(brandon): decide how to count collection attempts: in this table? via collect_jobs inspection? somehow else?
);

CREATE TABLE collect_jobs(
    id                    UUID DEFAULT gen_random_uuid() PRIMARY KEY, -- UUID used by collector to refer to this job
    task_id               BYTEA NOT NULL,      -- the task ID being collected
    batch_interval_start  TIMESTAMP NOT NULL,  -- the start of the batch interval
    batch_interval_end    TIMESTAMP NOT NULL,  -- the end of the batch interval
    aggregation_param     BYTEA NOT NULL,      -- the aggregation parameter (opaque VDAF message)

    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
