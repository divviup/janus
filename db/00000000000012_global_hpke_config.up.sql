CREATE TABLE global_hpke_keys(
    config_id SMALLINT PRIMARY KEY, -- HPKE config ID
    config BYTEA NOT NULL,          -- HPKE config, including public key (encoded HpkeConfig message)
    private_key BYTEA NOT NULL,     -- private key (encrypted)
    expired_at TIMESTAMP            -- when the key was marked for deletion
);
