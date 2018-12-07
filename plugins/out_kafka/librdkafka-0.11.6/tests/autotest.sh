#!/bin/bash
#
# autotest.sh runs the integration tests using a temporary Kafka cluster.
# This is intended to be used on CI.
#

set -e

KAFKA_VERSION=$1

if [[ -z $KAFKA_VERSION ]]; then
    echo "Usage: $0 <broker-version>"
    exit 1
fi

set -x

pushd tests

[[ -d _venv ]] || virtualenv _venv
source _venv/bin/activate

# Install trivup that is used to bring up a cluster.
pip install -U trivup

# Run tests that automatically spin up their clusters
export KAFKA_VERSION

echo "## Running full test suite for broker version $KAFKA_VERSION ##"
time make full


popd # tests
