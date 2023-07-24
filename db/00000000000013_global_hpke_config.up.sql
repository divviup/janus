CREATE TYPE HPKE_KEY_STATE AS ENUM(
    'ACTIVE',    -- the key should be advertised to DAP clients
    'PENDING',   -- the key should not be advertised to DAP clients, but could be used for
                 -- decrypting client reports depending on when aggregators pick up the state change
    'EXPIRED'    -- the key is pending deletion. it should not be advertised, but could be used
                 -- for decrypting client reports depending on the age of those reports
);

CREATE TABLE global_hpke_keys(
    -- These columns should be treated as immutable.
    config_id SMALLINT PRIMARY KEY,  -- HPKE config ID
    config BYTEA NOT NULL,           -- HPKE config, including public key (encoded HpkeConfig message)
    private_key BYTEA NOT NULL,      -- private key (encrypted)

    -- These columns are mutable.
    state HPKE_KEY_STATE NOT NULL DEFAULT 'PENDING',  -- state of the key
    updated_at TIMESTAMP NOT NULL                     -- when the key state was last changed
);
