#!/bin/bash
/usr/local/bin/janus_cli --config-file /etc/janus/janus_cli.yaml write-schema
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start janus_interop_aggregator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_creator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_driver
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start collection_job_driver
