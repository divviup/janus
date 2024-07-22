-- Per-task report aggregation counters, used for metrics.
--
-- Fillfactor is lowered to improve the likelihood of heap-only tuple optimizations. See the
-- discussion around this setting for the task_upload_counters table.
CREATE TABLE task_aggregation_counters(
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal only
    task_id  BIGINT NOT NULL,                                  -- task ID the counter is associated with
    ord      BIGINT NOT NULL,                                  -- the ordinal index of the task aggregation counter

    success  BIGINT NOT NULL DEFAULT 0,  -- reports successfully aggregated

    CONSTRAINT task_aggregation_counters_unique_id UNIQUE(task_id, ord),
    CONSTRAINT fk_task_id FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE CASCADE
) WITH (fillfactor = 50);
