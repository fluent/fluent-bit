### Description

This directory has a docker-compose file and its
configuration required to run:

1) A fluentbit installation with node-exporter enabled
2) Prometheus-server to gather metrics from fluentbit
3) A grafana installation with a default node-exporter 
dashboard enabled.

To run this, execute:

$ docker-compose up --force-recreate -d
