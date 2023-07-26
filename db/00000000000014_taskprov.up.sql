-- Describes how a task was created.
CREATE TYPE TASK_CREATED_BY AS ENUM(
    'MANUAL',         -- created by janus_cli, or otherwise manually by an operator.
    'AGGREGATOR_API', -- created by the aggregator API
    'TASKPROV',       -- created by taskprov
);

ALTER TABLE tasks ADD COLUMN created_by TASK_CREATED_BY NOT NULL;
ALTER TABLE tasks ADD COLUMN created_at TIMESTAMP NOT NULL;

-- Another DAP aggregator who we've partnered with to use the taskprov extension.
CREATE TABLE taskprov_peer_aggregator(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- artificial ID, internal only.
    endpoint TEXT NOT NULL,               -- peer aggregator HTTPS endpoint
    role AGGREGATOR_ROLE NOT NULL,        -- the role of this aggregator relative to the peer
    verify_key_init BYTEA NOT NULL,       -- the preshared key used for VDAF verify key derivation.
    collector_hpke_config BYTEA NOT NULL, -- the HPKE config of the collector (encoded HpkeConfig message)

    CONSTRAINT taskprov_peer_aggregator_endpoint_unique UNIQUE(endpoint)
);

-- Task aggregator auth tokens that we've shared with the peer aggregator.
CREATE TABLE taskprov_aggregator_auth_tokens(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    peer_aggregator_id BIGINT NOT NULL,  -- task ID the token is associated with
    ord BIGINT NOT NULL,                 -- a value used to specify the ordering of the authentication tokens
    token BYTEA NOT NULL,                -- bearer token used to authenticate messages to/from the other aggregator (encrypted)

    CONSTRAINT task_aggregator_auth_tokens_unique_peer_aggregator_id_and_ord UNIQUE(peer_aggregator_id, ord),
    CONSTRAINT fk_peer_aggregator_id FOREIGN KEY(peer_aggregator_id) REFERENCES peer_aggregator(id) ON DELETE CASCADE
);

-- Task collector auth tokens that we've shared with the peer aggregator.
CREATE TABLE taskprov_collector_auth_tokens(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- artificial ID, internal-only
    peer_aggregator_id BIGINT NOT NULL,  -- task ID the token is associated with
    ord BIGINT NOT NULL,                 -- a value used to specify the ordering of the authentication tokens
    token BYTEA NOT NULL,                -- bearer token used to authenticate messages to/from the other aggregator (encrypted)

    CONSTRAINT task_aggregator_auth_tokens_unique_peer_aggregator_id_and_ord UNIQUE(peer_aggregator_id, ord),
    CONSTRAINT fk_peer_aggregator_id FOREIGN KEY(peer_aggregator_id) REFERENCES peer_aggregator(id) ON DELETE CASCADE
);
