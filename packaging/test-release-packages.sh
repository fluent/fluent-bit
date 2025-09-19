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

INSTALL_CMD="curl $INSTALL_SCRIPT|sh"
EXTRA_MOUNTS=""
if [[ -f "$INSTALL_SCRIPT" ]]; then
    ABSOLUTE_PATH=$(realpath "$INSTALL_SCRIPT")
    EXTRA_MOUNTS="-v $ABSOLUTE_PATH:/install.sh:ro"
    INSTALL_CMD="/install.sh"
fi

# Optional check for specific version
VERSION_TO_CHECK_FOR=${VERSION_TO_CHECK_FOR:-}
function check_version() {
    if [[ -n "$VERSION_TO_CHECK_FOR" ]]; then
        local LOG_FILE=$1
        if grep -q "No package ${FLUENT_BIT_INSTALL_PACKAGE_NAME:-fluent-bit}-$VERSION_TO_CHECK_FOR available" "$LOG_FILE"; then
            echo "WARNING: Unable to install version: $VERSION_TO_CHECK_FOR"
            exit 1
        fi

        if ! grep -q "$VERSION_TO_CHECK_FOR" "$LOG_FILE"; then
            echo "WARNING: Not using expected version: $VERSION_TO_CHECK_FOR"
            exit 1
        fi
    fi
}

APT_TARGETS=(
	"ubuntu:22.04"
	"ubuntu:24.04"
    "debian:10"
    "debian:11"
	"debian:12"
	"debian:13"
)

YUM_TARGETS=(
	"centos:7"
    "almalinux:8"
    "almalinux:9"
    "almalinux:10"
    "rockylinux:8"
    "rockylinux:9"
    "rockylinux:10"
    "quay.io/centos/centos:stream9"
    "amazonlinux:2"
    "amazonlinux:2023"
)

for IMAGE in "${YUM_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    LOG_FILE=$(mktemp)

    VAULT=0
    # Fix to use Vault on CentOS 7
    case ${IMAGE} in
        centos:7)
            VAULT=1
            REPO_SCRIPT=$SCRIPT_DIR/centos7-repo.sh
            REPO_SCRIPT_PATH=$(realpath "$REPO_SCRIPT")
            EXTRA_MOUNTS="-v $REPO_SCRIPT_PATH:/centos7-repo.sh:ro $EXTRA_MOUNTS"
            ;;
        *)
            ;;
    esac

    # We do want word splitting for EXTRA_MOUNTS
    # shellcheck disable=SC2086
    $CONTAINER_RUNTIME run --rm -t \
        -e FLUENT_BIT_PACKAGES_URL="${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}" \
        -e FLUENT_BIT_PACKAGES_KEY="${FLUENT_BIT_PACKAGES_KEY:-https://packages.fluentbit.io/fluentbit.key}" \
        -e FLUENT_BIT_RELEASE_VERSION="${FLUENT_BIT_RELEASE_VERSION:-}" \
        -e FLUENT_BIT_INSTALL_COMMAND_PREFIX="${FLUENT_BIT_INSTALL_COMMAND_PREFIX:-}" \
        -e FLUENT_BIT_INSTALL_PACKAGE_NAME="${FLUENT_BIT_INSTALL_PACKAGE_NAME:-fluent-bit}" \
        -e FLUENT_BIT_INSTALL_YUM_PARAMETERS="${FLUENT_BIT_INSTALL_YUM_PARAMETERS:-}" \
        $EXTRA_MOUNTS \
        "$IMAGE" \
        sh -c "[ $VAULT -eq 1 ] && sh /centos7-repo.sh || true && $INSTALL_CMD && /opt/fluent-bit/bin/fluent-bit --version" | tee "$LOG_FILE"
    check_version "$LOG_FILE"
    rm -f "$LOG_FILE"
done

for IMAGE in "${APT_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    LOG_FILE=$(mktemp)
    # We do want word splitting for EXTRA_MOUNTS
    # shellcheck disable=SC2086
    $CONTAINER_RUNTIME run --rm -t \
        -e FLUENT_BIT_PACKAGES_URL="${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}" \
        -e FLUENT_BIT_PACKAGES_KEY="${FLUENT_BIT_PACKAGES_KEY:-https://packages.fluentbit.io/fluentbit.key}" \
        -e FLUENT_BIT_RELEASE_VERSION="${FLUENT_BIT_RELEASE_VERSION:-}" \
        -e FLUENT_BIT_INSTALL_COMMAND_PREFIX="${FLUENT_BIT_INSTALL_COMMAND_PREFIX:-}" \
        -e FLUENT_BIT_INSTALL_PACKAGE_NAME="${FLUENT_BIT_INSTALL_PACKAGE_NAME:-fluent-bit}" \
        -e FLUENT_BIT_INSTALL_APT_PARAMETERS="${FLUENT_BIT_INSTALL_APT_PARAMETERS:-}" \
        $EXTRA_MOUNTS \
        "$IMAGE" \
        sh -c "apt-get update && apt-get install -y gpg curl;$INSTALL_CMD && /opt/fluent-bit/bin/fluent-bit --version" | tee "$LOG_FILE"
    check_version "$LOG_FILE"
    rm -f "$LOG_FILE"
done
