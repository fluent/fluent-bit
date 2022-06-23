#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
# Verify package install for a release version

if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
fi

CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-docker}
INSTALL_SCRIPT=${INSTALL_SCRIPT:-https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh}

APT_TARGETS=("ubuntu:18.04"
    "ubuntu:20.04"
    "ubuntu:22.04"
    "debian:10"
    "debian:11")

YUM_TARGETS=("centos:7"
    "rockylinux:8"
    "amazonlinux:2")

for IMAGE in "${APT_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    $CONTAINER_RUNTIME run --rm -t \
        -e FLUENT_BIT_PACKAGES_URL="${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}" \
        -e FLUENT_BIT_PACKAGES_KEY="${FLUENT_BIT_PACKAGES_KEY:-https://packages.fluentbit.io/fluentbit.key}" \
        "$IMAGE" \
        sh -c "apt-get update && apt-get install -y sudo gpg curl;curl $INSTALL_SCRIPT | sh"
done

for IMAGE in "${YUM_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    $CONTAINER_RUNTIME run --rm -t \
        -e FLUENT_BIT_PACKAGES_URL="${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}" \
        -e FLUENT_BIT_PACKAGES_KEY="${FLUENT_BIT_PACKAGES_KEY:-https://packages.fluentbit.io/fluentbit.key}" \
        "$IMAGE" \
        sh -c "yum install -y curl sudo;curl $INSTALL_SCRIPT | sh"
done
