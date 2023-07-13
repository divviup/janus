-- A task_hpke_key with no task_id will be the global HPKE key.
ALTER TABLE task_hpke_keys ALTER COLUMN task_id DROP NOT NULL;

-- Ensure only one task_hpke_key can have a null task_id, ensuring that there
-- is only one global HPKE key.
CREATE UNIQUE INDEX task_hpke_keys_task_id_only_one_null ON task_hpke_keys((task_id IS NULL)) WHERE task_id IS NULL;