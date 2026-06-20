#!/bin/bash -ue

# shellcheck disable=SC1091
. /scripts/common.sh

wait_topic fb-sink

for i in $(seq 1 100); do
	sleep 1
	echo "{ \"name\": \"object-$i\" }" | \
		kafka-console-producer --topic fb-source \
		--broker-list "$KAFKA_HOST:$KAFKA_PORT"
done
