CREATE TABLE global_hpke_keys(
    config_id SMALLINT PRIMARY KEY, -- HPKE config ID
    config BYTEA NOT NULL,          -- HPKE config, including public key (encoded HpkeConfig message)
    private_key BYTEA NOT NULL,     -- private key (encrypted)
    is_active BOOLEAN NOT NULL,     -- whether the key should be advertised or not
    expired_at TIMESTAMP            -- when the key was marked for deletion
);
