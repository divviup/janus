DELETE FROM task_hpke_keys WHERE task_id IS NULL;
ALTER TABLE task_hpke_keys ALTER COLUMN task_id SET NOT NULL;
DROP INDEX task_hpke_keys_task_id_only_one_null;