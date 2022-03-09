#!/bin/bash -ue

# shellcheck disable=SC1091
. /scripts/common.sh

wait_topic fb-sink

exec /usr/local/bin/fluent-bit -c /etc/kafka.conf
