ALTER TABLE task_collector_auth_tokens DROP COLUMN type AUTH_TOKEN_TYPE;
ALTER TABLE task_aggregator_auth_tokens DROP COLUMN type AUTH_TOKEN_TYPE;

DROP TYPE AUTH_TOKEN_TYPE;
