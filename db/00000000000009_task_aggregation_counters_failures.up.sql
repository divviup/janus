ALTER TABLE task_aggregation_counters
    -- errors encountered by this aggregator
    ADD COLUMN duplicate_extension BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN public_share_encode_failure BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN batch_collected BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN report_replayed BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN report_dropped BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN hpke_unknown_config_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN hpke_decrypt_failure BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN vdaf_prep_error BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN task_expired BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN invalid_message BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN report_too_early BIGINT NOT NULL DEFAULT 0,

    -- errors reported by a peer helper aggregator
    ADD COLUMN helper_batch_collected BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_report_replayed BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_report_dropped BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_hpke_unknown_config_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_hpke_decrypt_failure BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_vdaf_prep_error BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_task_expired BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_invalid_message BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN helper_report_too_early BIGINT NOT NULL DEFAULT 0;
