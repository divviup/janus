-- TODO(brandon): remove pgcrypto extension once everyone is on Postgres 13+ w/ builtin gen_random_uuid
CREATE EXTENSION pgcrypto; -- for gen_random_uuid()

-- Identifies a particular VDAF.
CREATE TYPE VDAF_IDENTIFIER AS ENUM(
    'PRIO3_AES128_COUNT',
    'PRIO3_AES128_SUM',
    'PRIO3_AES128_HISTOGRAM',
    'POPLAR1'
);

-- Identifies which aggregator role is being played for this task.
CREATE TYPE AGGREGATOR_ROLE AS ENUM(
    'LEADER',
    'HELPER'
);

-- Corresponds to a PPM task, containing static data associated with the task.
CREATE TABLE tasks(
    id                     BYTEA PRIMARY KEY,         -- 32-byte TaskID as defined by the PPM specification
    aggregator_role        AGGREGATOR_ROLE NOT NULL,  -- the role of this aggregator for this task
    aggregator_endpoints   TEXT[] NOT NULL,           -- aggregator HTTPS endpoints, leader first
    vdaf                   VDAF_IDENTIFIER NOT NULL,  -- the VDAF in use for this task
    vdaf_verify_param      BYTEA NOT NULL,            -- the VDAF verify parameter (opaque VDAF message)
    max_batch_lifetime     BIGINT NOT NULL,           -- the maximum number of times a given batch may be collected
    min_batch_size         BIGINT NOT NULL,           -- the minimum number of reports in a batch to allow it to be collected
    min_batch_duration     BIGINT NOT NULL,           -- the minimum duration in seconds of a single batch interval
    tolerable_clock_skew   BIGINT NOT NULL,           -- the maximum acceptable clock skew to allow between client and aggregator, in seconds
    collector_hpke_config  BYTEA NOT NULL,            -- the HPKE config of the collector (encoded HpkeConfig message)
    agg_auth_key           BYTEA NOT NULL,            -- HMAC key used by this aggregator to authenticate messages to/from the other aggregator
    hpke_config            BYTEA NOT NULL,            -- the HPKE config of this aggregator (encoded HpkeConfig message)
    hpke_private_key       BYTEA NOT NULL             -- private key corresponding to hpke_config (hpke::HpkePrivateKey)

    -- TODO(timg): move vdaf_verify_param, agg_auth_key, hpke_config, hpke_private_key to new
    -- tables with many:1 relationships to tasks to allow for rotation of secrets
    -- TODO(timg): vdaf_verify_params, agg_auth_key and hpke_private_key should be encrypted
);

-- Individual reports received from clients.
CREATE TABLE client_reports(
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    task_id       BYTEA NOT NULL,      -- task ID the report is associated with
    nonce_time    TIMESTAMP NOT NULL,  -- timestamp from nonce
    nonce_rand    BYTEA NOT NULL,      -- random value from nonce
    extensions    BYTEA,               -- encoded sequence of Extension messages (populated for leader only)
    input_shares  BYTEA,               -- encoded sequence of HpkeCiphertext messages (populated for leader only)

    CONSTRAINT unique_task_id_and_nonce UNIQUE(task_id, nonce_time, nonce_rand),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
CREATE INDEX client_reports_task_and_time_index ON client_reports(task_id, nonce_time);

-- Specifies the possible state of an aggregation job.
CREATE TYPE AGGREGATION_JOB_STATE AS ENUM(
    'IN_PROGRESS', -- at least one included report is in a non-terminal (START, WAITING) state
    'FINISHED'     -- all reports have reached a terminal state (FINISHED, FAILED, INVALID)
);

-- An aggregation job, representing the aggregation of a number of client reports.
CREATE TABLE aggregation_jobs(
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    aggregation_job_id BYTEA NOT NULL,                  -- aggregation job ID
    task_id            BYTEA NOT NULL,                  -- ID of related task
    aggregation_param  BYTEA NOT NULL,                  -- encoded aggregation parameter (opaque VDAF message)
    state              AGGREGATION_JOB_STATE NOT NULL,  -- current state of the aggregation job

    CONSTRAINT unique_aggregation_job_id UNIQUE(aggregation_job_id),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- Specifies the possible state of aggregating a single report.
CREATE TYPE REPORT_AGGREGATION_STATE AS ENUM(
    'START',     -- the aggregator is waiting to decrypt its input share & compute initial preparation state
    'WAITING',   -- the aggregator is waiting for a message from its peer before proceeding
    'FINISHED',  -- the aggregator has completed the preparation process and recovered an output share
    'FAILED',    -- an error has occurred and an output share cannot be recovered
    'INVALID'    -- an aggregator received an unexpected message
);

-- An aggregation attempt for a single client report. An aggregation job logically contains a number
-- of report aggregations. A single client report might be aggregated in multiple aggregation jobs &
-- therefore have multiple associated report aggregations.
CREATE TABLE report_aggregations(
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    aggregation_job_id  BIGINT NOT NULL,                    -- the aggregation job ID this report aggregation is associated with
    client_report_id    BIGINT NOT NULL,                    -- the client report ID this report aggregation is associated with
    ord                 BIGINT NOT NULL,                    -- a value used to specify the ordering of client reports in the aggregation job
    state               REPORT_AGGREGATION_STATE NOT NULL,  -- the current state of this report aggregation
    vdaf_message        BYTEA,                              -- opaque VDAF message: the current preparation state if in state WAITING, the output share if in state FINISHED, null otherwise
    error_code          BIGINT,                             -- error code corresponding to a PPM TransitionError value; null if in a state other than FAILED

    CONSTRAINT unique_ord UNIQUE(aggregation_job_id, ord),
    CONSTRAINT fk_aggregation_job_id FOREIGN KEY(aggregation_job_id) REFERENCES aggregation_jobs(id),
    CONSTRAINT fk_client_report_id FOREIGN KEY(client_report_id) REFERENCES client_reports(id)
);
CREATE INDEX report_aggregations_aggregation_job_id_index ON report_aggregations(aggregation_job_id);

-- Information on aggregation for a single batch. This information may be incremental if the VDAF
-- supports incremental aggregation.
CREATE TABLE batch_aggregations(
    task_id               BYTEA NOT NULL,      -- the task ID
    batch_interval_start  TIMESTAMP NOT NULL,  -- the start of the batch interval
    aggregate_share       BYTEA NOT NULL,      -- the (possibly-incremental) aggregate share
    report_count          BIGINT NOT NULL,     -- the (possibly-incremental) client report count
    checksum              BYTEA NOT NULL,      -- the (possibly-incremental) checksum

    PRIMARY KEY(task_id, batch_interval_start)
);

-- A collection request from the Collector.
CREATE TABLE collect_jobs(
    id                    UUID DEFAULT gen_random_uuid() PRIMARY KEY, -- UUID used by collector to refer to this job
    task_id               BYTEA NOT NULL,      -- the task ID being collected
    batch_interval_start  TIMESTAMP NOT NULL,  -- the start of the batch interval
    batch_interval_end    TIMESTAMP NOT NULL,  -- the end of the batch interval
    aggregation_param     BYTEA NOT NULL,      -- the aggregation parameter (opaque VDAF message)

    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
CREATE INDEX collect_jobs_batch_interval_index ON collect_jobs(task_id, batch_interval_start, batch_interval_end);

-- An encrypted aggregate share computed for a specific collection job.
CREATE TABLE collect_job_encrypted_aggregate_shares(
    collect_job_id             UUID,             -- the ID of the collect job this encrypted aggregate share is associated with
    ord                        BIGINT NOT NULL,  -- the order of the aggregator associated with this encrypted_aggregate_share; 0 is leader, 1 or larger is helper
    encrypted_aggregate_share  BYTEA NOT NULL,   -- the encrypted aggregate share (an encoded HpkeCiphertext message)

    CONSTRAINT fk_collect_job_id FOREIGN KEY(collect_job_id) REFERENCES collect_jobs(id),
    PRIMARY KEY(collect_job_id, ord)
);
