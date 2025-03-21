#!/bin/bash -ue

# shellcheck disable=SC1091
. /scripts/common.sh

wait_topic fb-sink

kafka-console-consumer --topic fb-sink --bootstrap-server \
	"$KAFKA_HOST:$KAFKA_PORT"
