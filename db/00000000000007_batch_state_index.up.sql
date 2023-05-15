-- This migration is logically connected to the previous migration; we can't create the new index in
-- the same migration, as new enumerated values (COLLECTABLE) can't be used in the same transaction
-- they are created in.
CREATE INDEX collection_jobs_state_and_lease_expiry ON collection_jobs(state, lease_expiry) WHERE state = 'COLLECTABLE';
DROP INDEX collection_jobs_lease_expiry;
