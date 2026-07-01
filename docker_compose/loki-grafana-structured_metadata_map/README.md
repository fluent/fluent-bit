### Description

This directory has a docker-compose file and its
configuration required to run:

1) A fluentbit installation with a dummy input, and Loki output configured for `structured_metadata_map_keys`
3) A Loki installation 
4) A grafana installation with a default Loki datasource

To run this, execute:

$ docker-compose up --force-recreate -d

n.b., the [docker compose file](./docker-compose.yml) contains an `image` and a commented out `build` section. Change
these to build from local source.