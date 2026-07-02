#!/bin/bash
set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <kafka-version> <cp-version> [<consumer_group_protocol>]"
    echo "Example: $0 3.9.0 7.9.0"
    exit 1
fi

KAFKA_VERSION=$1
CP_VERSION=$2
if [ -n "$3" ]; then
    export TEST_CONSUMER_GROUP_PROTOCOL=$3
fi

source /home/user/venv/bin/activate
./configure --install-deps --enable-werror --enable-devel
./packaging/tools/rdutcoverage.sh
make copyright-check
make -j all examples check
echo "Verifying that CONFIGURATION.md does not have manual changes"
git diff --exit-code CONFIGURATION.md
examples/rdkafka_example -X builtin.features
ldd src/librdkafka.so.1
ldd src-cpp/librdkafka++.so.1
make -j -C tests build
make -C tests run_local_quick
DESTDIR="$PWD/dest" make install
(cd tests && python3 -m trivup.clusters.KafkaCluster --kraft \
 --conf '["group.share.min.record.lock.duration.ms=1000"]' \
 --version ${KAFKA_VERSION} \
 --cpversion ${CP_VERSION} --cmd 'make quick')
