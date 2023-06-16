ALTER TABLE report_aggregations DROP CONSTRAINT fk_client_report_id;
ALTER TABLE report_aggregations DROP COLUMN client_report_id;
ALTER TABLE report_aggregations ADD COLUMN client_report_id BYTEA NOT NULL;
ALTER TABLE report_aggregations ADD COLUMN client_timestamp TIMESTAMP NOT NULL; -- the client timestamp this report aggregation is associated with
CREATE INDEX report_aggregations_client_report_id_index ON report_aggregations(client_report_id);
