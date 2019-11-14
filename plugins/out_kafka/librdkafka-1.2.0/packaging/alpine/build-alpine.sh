#!/bin/sh
#
# Build librdkafka on Alpine.
#

set -x

if [ "$1" = "--in-docker" ]; then
    # Runs in docker, performs the actual build.

    apk add bash curl gcc g++ make musl-dev bsd-compat-headers git python perl

    git clone /v /librdkafka

    cd /librdkafka
    ./configure --install-deps --disable-gssapi --disable-lz4-ext --enable-static
    make -j
    examples/rdkafka_example -X builtin.features
    make -C tests run_local

    # Create a tarball in artifacts/
    cd src
    ldd librdkafka.so.1
    tar cvzf /v/artifacts/alpine-librdkafka.tgz librdkafka.so.1
    cd ../..

else
    # Runs on the host, simply spins up the in-docker build.
    if [ ! -f configure.self ]; then
        echo "Must be run from the top-level librdkafka dir"
        exit 1
    fi

    mkdir -p artifacts

    exec docker run -v $PWD:/v alpine:3.8 /v/packaging/alpine/$(basename $0) --in-docker
fi
