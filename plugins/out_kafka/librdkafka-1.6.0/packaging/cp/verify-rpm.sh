#!/bin/bash
#

set -e

cpver=$1
base_url=$2

if [[ -z $base_url ]]; then
    echo "Usage: $0 <cp-base-ver> <base_url>"
    exit 1
fi

cat >/etc/yum.repos.d/Confluent.repo <<EOF
[Confluent.dist]
name=Confluent repository (dist)
baseurl=$base_url/rpm/${cpver}/7
gpgcheck=0
gpgkey=$base_url/rpm/${cpver}/archive.key
enabled=1
[Confluent]
name=Confluent repository
baseurl=$base_url/rpm/${cpver}
gpgcheck=1
gpgkey=$base_url/rpm/${cpver}/archive.key
enabled=1
EOF

yum install -y librdkafka-devel gcc

gcc /v/check_features.c -o /tmp/check_features -lrdkafka

/tmp/check_features

# Verify plugins
yum install -y confluent-librdkafka-plugins

/tmp/check_features plugin.library.paths monitoring-interceptor
