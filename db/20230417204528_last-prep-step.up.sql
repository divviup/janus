-- Note that this migration cannot be applied to a database with reports in it -- we have opted not to write tooling to transform and backfill data, since we don't currently have need for it.

ALTER TABLE report_aggregations ADD COLUMN last_prep_step BYTEA;  -- the last PreparationStep message sent to the Leader, to assist in replay (opaque VDAF message, populated for Helper only)

-- Additionally, the purpose of report_aggregations.prep_msg has changed. It is now the next preparation message to be sent to the helper. It is an opaque VDAF message, and populated for the Leader only.
