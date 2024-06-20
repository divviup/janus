ALTER TABLE global_hpke_keys
    ALTER COLUMN last_state_change_at SET DEFAULT '-infinity'::TIMESTAMP,
    ALTER COLUMN last_state_change_at DROP NOT NULL;
