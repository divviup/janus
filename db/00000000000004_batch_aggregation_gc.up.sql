-- Used to identify batch aggregations which can be garbage collected.
CREATE INDEX batch_aggregations_gc_time ON batch_aggregations(task_id, UPPER(COALESCE(batch_interval, client_timestamp_interval)));
