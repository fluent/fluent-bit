#!/bin/bash
#
# Build librdkafka on Alpine using Docker, and run the local test suite.
#

set -eu
echo -e "\033[35m### Building on Alpine ###\033[0m"
exec docker run -v $PWD:/v alpine:3.8 /v/packaging/alpine/test-build-alpine.sh
