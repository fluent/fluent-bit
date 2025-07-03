#!/bin/bash
#

set -e

base_url=$1
version=$2

if [[ -z $base_url ]]; then
    echo "Usage: $0 <base_url>"
    exit 1
fi

apt-get update
apt-get install -y apt-transport-https wget gnupg2 lsb-release

wget -qO - ${base_url}/clients/deb/archive.key | apt-key add -

release=$(lsb_release -cs)
cat >/etc/apt/sources.list.d/Confluent.list <<EOF
deb $base_url/clients/deb ${release} main
EOF

apt-get update
apt-get install -y librdkafka-dev gcc

gcc /v/check_features.c -o /tmp/check_features -lrdkafka

/tmp/check_features $version

# FIXME: publish plugins in newer versions
# apt-get install -y confluent-librdkafka-plugins
#/tmp/check_features plugin.library.paths monitoring-interceptor
