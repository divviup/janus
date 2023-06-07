CREATE TYPE AUTH_TOKEN_TYPE AS ENUM(
    'DAP_AUTH', -- DAP-01 style DAP-Auth-Token header
    'BEARER' -- RFC 6750 bearer token
);

ALTER TABLE task_aggregator_auth_tokens ADD COLUMN type AUTH_TOKEN_TYPE NOT NULL DEFAULT 'DAP_AUTH';
ALTER TABLE task_collector_auth_tokens ADD COLUMN type AUTH_TOKEN_TYPE NOT NULL DEFAULT 'DAP_AUTH';
