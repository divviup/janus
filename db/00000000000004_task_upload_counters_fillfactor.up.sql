-- This table is extremely update-heavy and the updates should qualify for the
-- heap-only tuple optimization. Leave enough space per heap page for HOT updates.
--
-- Setting the exact fillfactor is a tradeoff between disk space and likelihood
-- of HOT updates. We don't want to set fillfactor too low and waste disk space.
-- 50 represents a 2x table size bump, which seems like an acceptible tradeoff.
--
-- See https://www.postgresql.org/docs/current/storage-hot.html
ALTER TABLE task_upload_counters SET (fillfactor = 50);
