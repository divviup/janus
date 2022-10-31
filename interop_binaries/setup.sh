#!/bin/bash
/usr/local/bin/janus_cli write-schema --config-file /etc/janus/janus_cli.yaml
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start janus_interop_aggregator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_creator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_driver
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start collect_job_driver
