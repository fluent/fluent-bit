#!/bin/bash -ue

# shellcheck disable=SC1091
. /scripts/common.sh

wait_kafka

kafka-topics --create --partitions 1 --replication-factor 1 --topic fb-source --bootstrap-server "$KAFKA_HOST:$KAFKA_PORT"
kafka-topics --create --partitions 1 --replication-factor 1 --topic fb-sink --bootstrap-server "$KAFKA_HOST:$KAFKA_PORT"
