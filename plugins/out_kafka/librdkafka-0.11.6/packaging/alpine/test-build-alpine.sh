#!/bin/sh
#
#
# Build librdkafka on Alpine.
# Must only be run from within an Alpine container where
# the librdkafka root dir is mounted as /v
#

set -eu

if [ ! -f /.dockerenv ] ; then
    echo "$0 must be run in the docker container"
    exit 1
fi

apk add bash gcc g++ make musl-dev bsd-compat-headers git python

git clone /v /librdkafka

cd /librdkafka
./configure
make
make -C tests run_local
cd ..
