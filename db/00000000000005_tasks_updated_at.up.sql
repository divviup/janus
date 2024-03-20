-- This column needs to be nullable for this migration to be zero downtime.
ALTER TABLE tasks ADD COLUMN updated_at TIMESTAMP;
