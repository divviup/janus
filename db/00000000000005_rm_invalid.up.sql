-- Remove the INVALID report aggregation state. We have to create a new type & drop the old type
-- as enumerated values can't be directly removed from an enum type.
-- See: https://stackoverflow.com/questions/25811017/how-to-delete-an-enum-type-value-in-postgres

CREATE TYPE REPORT_AGGREGATION_STATE_NEW AS ENUM(
    'START',     -- the aggregator is waiting to decrypt its input share & compute initial preparation state
    'WAITING',   -- the aggregator is waiting for a message from its peer before proceeding
    'FINISHED',  -- the aggregator has completed the preparation process and recovered an output share
    'FAILED'     -- an error has occurred and an output share cannot be recovered
);
ALTER TABLE report_aggregations ALTER COLUMN state TYPE REPORT_AGGREGATION_STATE_NEW
    USING (state::text::REPORT_AGGREGATION_STATE_NEW);
DROP TYPE REPORT_AGGREGATION_STATE;
ALTER TYPE REPORT_AGGREGATION_STATE_NEW RENAME TO REPORT_AGGREGATION_STATE;