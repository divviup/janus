-- Load pgcrypto for gen_random_bytes.
CREATE EXTENSION pgcrypto;
-- Load an extension to allow indexing over both BIGINT and TSRANGE in a
-- multicolumn GiST index.
CREATE EXTENSION btree_gist;

-- Identifies which aggregator role is being played for this task.
CREATE TYPE AGGREGATOR_ROLE AS ENUM(
    'LEADER',
    'HELPER'
);

-- Corresponds to a PPM task, containing static data associated with the task.
CREATE TABLE tasks(
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id                BYTEA UNIQUE NOT NULL,     -- 32-byte TaskID as defined by the PPM specification
    aggregator_role        AGGREGATOR_ROLE NOT NULL,  -- the role of this aggregator for this task
    aggregator_endpoints   TEXT[] NOT NULL,           -- aggregator HTTPS endpoints, leader first
    vdaf                   JSON NOT NULL,             -- the VDAF instance in use for this task, along with its parameters
    max_batch_lifetime     BIGINT NOT NULL,           -- the maximum number of times a given batch may be collected
    min_batch_size         BIGINT NOT NULL,           -- the minimum number of reports in a batch to allow it to be collected
    min_batch_duration     BIGINT NOT NULL,           -- the minimum duration in seconds of a single batch interval
    tolerable_clock_skew   BIGINT NOT NULL,           -- the maximum acceptable clock skew to allow between client and aggregator, in seconds
    collector_hpke_config  BYTEA NOT NULL             -- the HPKE config of the collector (encoded HpkeConfig message)
);

-- The aggregator authentication tokens used by a given task.
CREATE TABLE task_aggregator_auth_tokens(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id BIGINT NOT NULL,  -- task ID the token is associated with
    ord BIGINT NOT NULL,      -- a value used to specify the ordering of the authentication tokens
    token BYTEA NOT NULL,     -- bearer token used to authenticate messages to/from the other aggregator (encrypted)

    CONSTRAINT aggregator_auth_token_unique_task_id_and_ord UNIQUE(task_id, ord),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- The collector authentication tokens used by a given task.
CREATE TABLE task_collector_auth_tokens(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id BIGINT NOT NULL,  -- task ID the token is associated with
    ord BIGINT NOT NULL,      -- a value used to specify the ordering of the authentication tokens
    token BYTEA NOT NULL,     -- bearer token used to authenticate messages from the collector (encrypted)

    CONSTRAINT collector_auth_token_unique_task_id_and_ord UNIQUE(task_id, ord),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- The HPKE public keys (aka configs) and private keys used by a given task.
CREATE TABLE task_hpke_keys(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id BIGINT NOT NULL,      -- task ID the HPKE key is associated with
    config_id SMALLINT NOT NULL,  -- HPKE config ID
    config BYTEA NOT NULL,        -- HPKE config, including public key (encoded HpkeConfig message)
    private_key BYTEA NOT NULL,   -- private key (encrypted)

    CONSTRAINT unique_task_id_and_config_id UNIQUE(task_id, config_id),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- The VDAF verification keys used by a given task.
-- TODO(#229): support multiple verification parameters per task
CREATE TABLE task_vdaf_verify_keys(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id BIGINT NOT NULL,         -- task ID the verification key is associated with
    vdaf_verify_key BYTEA NOT NULL,  -- the VDAF verification key (encrypted)

    CONSTRAINT vdaf_verify_key_unique_task_id UNIQUE(task_id),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- Individual reports received from clients.
CREATE TABLE client_reports(
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    task_id       BIGINT NOT NULL,     -- task ID the report is associated with
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
    'IN_PROGRESS', -- at least one included report is in a non-terminal (START, WAITING) state, processing can continue
    'FINISHED',    -- all reports have reached a terminal state (FINISHED, FAILED, INVALID)
    'ABANDONED'    -- we have given up on the aggregation job entirely
);

-- An aggregation job, representing the aggregation of a number of client reports.
CREATE TABLE aggregation_jobs(
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    task_id            BIGINT NOT NULL,                 -- ID of related task
    aggregation_job_id BYTEA NOT NULL,                  -- 32-byte AggregationJobID as defined by the PPM specification
    aggregation_param  BYTEA NOT NULL,                  -- encoded aggregation parameter (opaque VDAF message)
    state              AGGREGATION_JOB_STATE NOT NULL,  -- current state of the aggregation job

    lease_expiry       TIMESTAMP NOT NULL DEFAULT TIMESTAMP '-infinity',  -- when lease on this aggregation job expires; -infinity implies no current lease
    lease_token        BYTEA,                                             -- a value identifying the current leaseholder; NULL implies no current lease
    lease_attempts     BIGINT NOT NULL DEFAULT 0,                         -- the number of lease acquiries since the last successful lease release

    CONSTRAINT unique_aggregation_job_id UNIQUE(aggregation_job_id),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
CREATE INDEX aggregation_jobs_state_and_lease_expiry ON aggregation_jobs(state, lease_expiry) WHERE state = 'IN_PROGRESS';

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
    prep_state          BYTEA,                              -- the current preparation state (opaque VDAF message, only if in state WAITING)
    prep_msg            BYTEA,                              -- the next preparation message to be sent to the helper (opaque VDAF message, only if in state WAITING if this aggregator is the leader)
    out_share           BYTEA,                              -- the output share (opaque VDAF message, only if in state FINISHED)
    error_code          BIGINT,                             -- error code corresponding to a PPM ReportShareError value; null if in a state other than FAILED

    CONSTRAINT unique_ord UNIQUE(aggregation_job_id, ord),
    CONSTRAINT fk_aggregation_job_id FOREIGN KEY(aggregation_job_id) REFERENCES aggregation_jobs(id),
    CONSTRAINT fk_client_report_id FOREIGN KEY(client_report_id) REFERENCES client_reports(id)
);
CREATE INDEX report_aggregations_aggregation_job_id_index ON report_aggregations(aggregation_job_id);
CREATE INDEX report_aggregations_client_report_id_index ON report_aggregations(client_report_id);

-- Information on aggregation for a single batch unit. This information may be incremental if the
-- VDAF supports incremental aggregation.
CREATE TABLE batch_unit_aggregations(
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id               BIGINT NOT NULL,     -- the task ID
    unit_interval_start   TIMESTAMP NOT NULL,  -- the start of the batch unit
    aggregation_param     BYTEA NOT NULL,      -- the aggregation parameter (opaque VDAF message)
    aggregate_share       BYTEA NOT NULL,      -- the (possibly-incremental) aggregate share
    report_count          BIGINT NOT NULL,     -- the (possibly-incremental) client report count
    checksum              BYTEA NOT NULL,      -- the (possibly-incremental) checksum

    CONSTRAINT unique_task_id_interval_aggregation_param UNIQUE(task_id, unit_interval_start, aggregation_param),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);

-- Specifies the possible state of a collect job.
CREATE TYPE COLLECT_JOB_STATE AS ENUM(
    'START',     -- the aggregator is waiting to run this collect job
    'FINISHED',  -- this collect job has run successfully and is ready for collection
    'ABANDONED'  -- this collect job has been abandoned & will never be run again
);

-- The leader's view of collect requests from the Collector.
CREATE TABLE collect_jobs(
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    collect_job_id          UUID NOT NULL,               -- UUID used by collector to refer to this job
    task_id                 BIGINT NOT NULL,             -- the task ID being collected
    batch_interval          TSRANGE NOT NULL,            -- the batch interval, as a range of timestamps
    aggregation_param       BYTEA NOT NULL,              -- the aggregation parameter (opaque VDAF message)
    state                   COLLECT_JOB_STATE NOT NULL,  -- the current state of this collect job
    helper_aggregate_share  BYTEA,                       -- the helper's encrypted aggregate share (HpkeCiphertext, only if in state FINISHED)
    leader_aggregate_share  BYTEA,                       -- the leader's unencrypted aggregate share (opaque VDAF message, only if in state FINISHED)

    lease_expiry            TIMESTAMP NOT NULL DEFAULT TIMESTAMP '-infinity',  -- when lease on this collect job expires; -infinity implies no current lease
    lease_token             BYTEA,                                             -- a value identifying the current leaseholder; NULL implies no current lease
    lease_attempts          BIGINT NOT NULL DEFAULT 0,                         -- the number of lease acquiries since the last successful lease release

    CONSTRAINT unique_collect_job_task_id_interval_aggregation_param UNIQUE(task_id, batch_interval, aggregation_param),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
-- TODO(#224): verify that this index is optimal for purposes of acquiring collect jobs.
CREATE INDEX collect_jobs_lease_expiry ON collect_jobs(lease_expiry);
CREATE INDEX collect_jobs_interval_containment_index ON collect_jobs USING gist (task_id, batch_interval);

-- The helper's view of aggregate share jobs.
CREATE TABLE aggregate_share_jobs(
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal-only
    task_id                 BIGINT NOT NULL,    -- the task ID being collected
    batch_interval          TSRANGE NOT NULL,   -- the batch interval, as a range of timestamps
    aggregation_param       BYTEA NOT NULL,     -- the aggregation parameter (opaque VDAF message)
    helper_aggregate_share  BYTEA NOT NULL,     -- the helper's unencrypted aggregate share
    report_count            BIGINT NOT NULL,    -- the count of reports included helper_aggregate_share
    checksum                BYTEA NOT NULL,     -- the checksum over the reports included in helper_aggregate_share

    CONSTRAINT unique_aggregate_share_job_task_id_interval_aggregation_param UNIQUE(task_id, batch_interval, aggregation_param),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id)
);
CREATE INDEX aggregate_share_jobs_interval_containment_index ON aggregate_share_jobs USING gist (task_id, batch_interval);
