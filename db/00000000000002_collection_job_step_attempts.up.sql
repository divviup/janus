-- step_attempts is the number of attempts to step the collection job without making progress,
-- regardless of whether the lease was successfully released or not.
ALTER TABLE collection_jobs ADD COLUMN step_attempts BIGINT NOT NULL DEFAULT 0;
