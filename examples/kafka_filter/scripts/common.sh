#!/bin/bash -ue

wait_kafka() {
	while ! nc -z "$KAFKA_HOST" "$KAFKA_PORT"; do
		sleep 0.1
	done
}

wait_topic() {
	wait_kafka
	local topic=$1
	[ -z "$topic" ] && return 1
	while true; do
		kafka-topics --list --bootstrap-server "$KAFKA_HOST:$KAFKA_PORT" | grep -q "^$topic$" && break
		sleep 0.1
	done
}
