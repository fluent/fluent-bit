#!/bin/bash
set -eux
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Simple script to test all supported targets easily.

RELEASE_URL=${RELEASE_URL:-https://packages.fluentbit.io}
STAGING_URL=${STAGING_URL:-https://fluentbit-staging.s3.amazonaws.com}

for DOCKERFILE in "$SCRIPT_DIR"/Dockerfile.*; do
    DISTRO=${DOCKERFILE##*.}
    echo "Testing $DISTRO"
    PACKAGE_TEST="$DISTRO" RELEASE_URL="$RELEASE_URL" STAGING_URL="$STAGING_URL" "$SCRIPT_DIR"/run-package-tests.sh
done