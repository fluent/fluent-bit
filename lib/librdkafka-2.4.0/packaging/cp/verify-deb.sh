#!/bin/bash
#

set -e

cpver=$1
base_url=$2

if [[ -z $base_url ]]; then
    echo "Usage: $0 <cp-base-ver> <base_url>"
    exit 1
fi

apt-get update
apt-get install -y apt-transport-https wget

wget -qO - ${base_url}/deb/${cpver}/archive.key | apt-key add -


cat >/etc/apt/sources.list.d/Confluent.list <<EOF
deb [arch=amd64] $base_url/deb/${cpver} stable main
EOF

apt-get update
apt-get install -y librdkafka-dev gcc

gcc /v/check_features.c -o /tmp/check_features -lrdkafka

/tmp/check_features

# Verify plugins
apt-get install -y confluent-librdkafka-plugins

/tmp/check_features plugin.library.paths monitoring-interceptor
