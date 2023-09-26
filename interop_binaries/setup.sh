#!/bin/bash
until pg_isready -U postgres; do sleep 1; done
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start janus_interop_aggregator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_creator
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start aggregation_job_driver
/usr/bin/supervisorctl -c /etc/janus/supervisord.conf start collection_job_driver
