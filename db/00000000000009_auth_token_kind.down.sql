ALTER TABLE task_collector_auth_tokens DROP COLUMN type;
ALTER TABLE task_aggregator_auth_tokens DROP COLUMN type;

DROP TYPE AUTH_TOKEN_TYPE;
