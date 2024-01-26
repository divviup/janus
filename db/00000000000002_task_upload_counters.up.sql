-- Per task report upload counters.
CREATE TABLE task_upload_counters(
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    task_id                BIGINT NOT NULL,

    interval_collected     BIGINT NOT NULL DEFAULT 0, -- Reports submitted for an interval that was already collected.
    report_decode_failure  BIGINT NOT NULL DEFAULT 0, -- Reports which failed to decode.
    report_decrypt_failure BIGINT NOT NULL DEFAULT 0, -- Reports which failed to decrypt.
    report_expired         BIGINT NOT NULL DEFAULT 0, -- Reports that were older than the task's report_expiry_age.
    report_outdated_key    BIGINT NOT NULL DEFAULT 0, -- Reports that were encrypted with an unknown or outdated HPKE key.
    report_success         BIGINT NOT NULL DEFAULT 0, -- Reports that were successfully uploaded.
    report_too_early       BIGINT NOT NULL DEFAULT 0, -- Reports whose timestamp is too far in the future.
    task_expired           BIGINT NOT NULL DEFAULT 0, -- Reports sent to the task while it is expired.

    ord                    BIGINT NOT NULL,           -- Index of this task_upload_counters shard.

    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    CONSTRAINT task_upload_counters_unique UNIQUE(task_id, ord)
);
