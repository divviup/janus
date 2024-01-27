ALTER TABLE report_aggregations ADD COLUMN public_share BYTEA;  -- the public share for the report (opaque VDAF message)
ALTER TABLE report_aggregations ADD COLUMN leader_extensions BYTEA;  -- encoded sequence of Extension messages from Leader input share (opaque DAP messages)
ALTER TABLE report_aggregations ADD COLUMN leader_input_share BYTEA;  -- encoded leader input share (opaque VDAF message)
ALTER TABLE report_aggregations ADD COLUMN helper_encrypted_input_share BYTEA;  -- encoded HPKE ciphertext of helper input share (opaque DAP message)

