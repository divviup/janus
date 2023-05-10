-- We can't remove the COLLECTABLE enum type as removing values from an enum type is not supported
-- by Postgres.

DROP TABLE batches;
DROP TYPE BATCH_STATE CASCADE;
