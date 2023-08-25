ALTER TABLE aggregation_jobs ADD COLUMN trace_context jsonb;
ALTER TABLE collection_jobs ADD COLUMN trace_context jsonb;
