ALTER TABLE task_aggregation_counters
    ADD COLUMN helper_batch_collected BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_report_replayed BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_report_dropped BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_hpke_unknown_config_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_hpke_decrypt_failure BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_vdaf_prep_error BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_task_expired BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_invalid_message BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_report_too_early BIGINT NOT NULL DEFAULT 0;
