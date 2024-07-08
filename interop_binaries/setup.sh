#!/bin/bash
set -e

timeout 5m bash -c 'until pg_isready -U postgres; do sleep 1; done'
sqlx migrate run --source /etc/janus/migrations --database-url postgres://postgres@127.0.0.1:5432/postgres
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start janus_interop_aggregator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_creator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_driver
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start collection_job_driver
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start key_rotator
