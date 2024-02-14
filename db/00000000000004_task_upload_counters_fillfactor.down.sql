-- The default table fillfactor in postgres is 100.
ALTER TABLE task_upload_counters SET (fillfactor = 100);
