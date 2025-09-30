#!/bin/bash
#

set -e

# Test current librdkafka with multiple broker versions.

if [[ ! -z $TEST_KAFKA_VERSION ]]; then
    echo "Must not be run from within a trivup session"
    exit 1
fi


VERSIONS="$*"
if [[ -z $VERSIONS ]]; then
    VERSIONS="0.8.2.1 0.9.0.1 0.10.0.1 0.10.1.1 0.10.2.1 0.11.0.0"
fi

FAILED_VERSIONS=""
PASSED_VERSIONS=""
for VERSION in $VERSIONS ; do
    echo "Testing broker version $VERSION"
    if [[ $VERSION == "trunk" ]]; then
        extra_args="--kafka-src ~/src/kafka --no-deploy"
    else
        extra_args=""
    fi
    ./interactive_broker_version.py \
        --root ~/old/kafka -c "make run_seq" $extra_args "$VERSION"

    if [[ $? == 0 ]] ; then
        echo "#### broker $VERSION passed ####"
        PASSED_VERSIONS="${PASSED_VERSIONS}${VERSION} "
    else
        echo "#### broker $VERSION FAILED ####"
        FAILED_VERSIONS="${FAILED_VERSIONS}${VERSION} "
    fi
done


echo "broker versions PASSED: ${PASSED_VERSIONS}"
echo "broker versions FAILED: ${FAILED_VERSIONS}"

if [[ ! -z $FAILED_VERSIONS ]]; then
    exit 1
else
    exit 0
fi


