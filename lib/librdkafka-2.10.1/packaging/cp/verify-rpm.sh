#!/bin/bash
#

set -e

base_url=$1
version=$2

if [[ -z $base_url ]]; then
    echo "Usage: $0 <base_url>"
    exit 1
fi

cat >/etc/yum.repos.d/Confluent.repo <<EOF
[Confluent-Clients]
name=Confluent Clients repository
baseurl=$base_url/clients/rpm/centos/\$releasever/\$basearch
gpgcheck=1
gpgkey=$base_url/clients/rpm/archive.key
enabled=1
EOF

yum install -y librdkafka-devel gcc

gcc /v/check_features.c -o /tmp/check_features -lrdkafka

/tmp/check_features $version

# Verify plugins
# yum install -y confluent-librdkafka-plugins

# /tmp/check_features plugin.library.paths monitoring-interceptor
