-- When the key state was last changed. Used for key rotation logic.
ALTER TABLE global_hpke_keys
    ADD COLUMN last_state_change_at TIMESTAMP NOT NULL DEFAULT '-infinity'::TIMESTAMP;

-- Backfill new column using updated_at. Older Janus versions aren't aware of
-- this column, so state change operations on this table won't update the new
-- column. However, this is an infrequently used table that is only manually
-- modified (at the time of writing), so the risk of corruption due to this is
-- low. In the worst case, the key rotator service will induce a rotation of
-- any keys with `-infinity`.
UPDATE global_hpke_keys SET last_state_change_at = updated_at;
