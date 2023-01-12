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

# Optional check for specific version
VERSION_TO_CHECK_FOR=${VERSION_TO_CHECK_FOR:-}
function check_version() {
    if [[ -n "$VERSION_TO_CHECK_FOR" ]]; then
        local LOG_FILE=$1
        if ! grep -q "$VERSION_TO_CHECK_FOR" "$LOG_FILE"; then
            echo "WARNING: Not using expected version: $VERSION_TO_CHECK_FOR"
            exit 1
        fi
    fi
}

APT_TARGETS=("ubuntu:18.04"
    "ubuntu:20.04"
    "ubuntu:22.04"
    "debian:10"
    "debian:11")

YUM_TARGETS=("centos:7"
    "rockylinux:8"
    "quay.io/centos/centos:stream9"
    "amazonlinux:2"
    "amazonlinux:2022")

for IMAGE in "${APT_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    LOG_FILE=$(mktemp)
    $CONTAINER_RUNTIME run --rm -t \
        -e FLUENT_BIT_PACKAGES_URL="${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}" \
        -e FLUENT_BIT_PACKAGES_KEY="${FLUENT_BIT_PACKAGES_KEY:-https://packages.fluentbit.io/fluentbit.key}" \
        "$IMAGE" \
        sh -c "apt-get update && apt-get install -y gpg curl;curl $INSTALL_SCRIPT | sh && /opt/fluent-bit/bin/fluent-bit --version" | tee "$LOG_FILE"
    check_version "$LOG_FILE"
    rm -f "$LOG_FILE"
done

for IMAGE in "${YUM_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    LOG_FILE=$(mktemp)
    $CONTAINER_RUNTIME run --rm -t \
        -e FLUENT_BIT_PACKAGES_URL="${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}" \
        -e FLUENT_BIT_PACKAGES_KEY="${FLUENT_BIT_PACKAGES_KEY:-https://packages.fluentbit.io/fluentbit.key}" \
        "$IMAGE" \
        sh -c "curl $INSTALL_SCRIPT | sh && /opt/fluent-bit/bin/fluent-bit --version" | tee "$LOG_FILE"
    check_version "$LOG_FILE"
    rm -f "$LOG_FILE"
done
