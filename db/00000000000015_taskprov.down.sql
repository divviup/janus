DROP TABLE taskprov_aggregator_auth_tokens;
DROP TABLE taskprov_collector_auth_tokens;
DROP TABLE taskprov_peer_aggregators;
ALTER TABLE tasks ALTER COLUMN collector_hpke_config SET NOT NULL;
