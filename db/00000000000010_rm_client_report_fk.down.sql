ALTER TABLE report_aggregations DROP COLUMN client_timestamp;
ALTER TABLE report_aggregations DROP COLUMN client_report_id;
ALTER TABLE report_aggregations ADD COLUMN client_report_id BIGINT NOT NULL;
ALTER TABLE report_aggregations ADD CONSTRAINT fk_client_report_id FOREIGN KEY(client_report_id) REFERENCES client_reports(id) ON DELETE CASCADE;
CREATE INDEX report_aggregations_client_report_id_index ON report_aggregations(client_report_id);
