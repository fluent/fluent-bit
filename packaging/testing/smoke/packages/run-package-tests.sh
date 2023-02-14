#!/bin/bash
# Copyright 2021 Calyptia, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file  except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the  License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -eux
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

PACKAGE_TEST=${PACKAGE_TEST:-centos7}
RELEASE_URL=${RELEASE_URL:-https://packages.fluentbit.io}
RELEASE_KEY=${RELEASE_KEY:-https://packages.fluentbit.io/fluentbit.key}
STAGING_URL=${STAGING_URL:-https://fluentbit-staging.s3.amazonaws.com}
STAGING_KEY=${STAGING_KEY:-https://fluentbit-staging.s3.amazonaws.com/fluentbit.key}

# Podman is preferred as better systemd support and cgroups handling
CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-podman}

if [[ ! -f "$SCRIPT_DIR/Dockerfile.$PACKAGE_TEST" ]]; then
    echo "No definition for $SCRIPT_DIR/Dockerfile.$PACKAGE_TEST"
    exit 1
fi

declare -a CONTAINER_TARGETS=("official-install" "staging-install" "staging-upgrade")

# Build all containers required
for TARGET in "${CONTAINER_TARGETS[@]}"
do
    BUILD_ARGS=""
    if [[ $TARGET == "staging-upgrade" ]]; then
        BUILD_ARGS="--build-arg STAGING_BASE=staging-upgrade-prep"
    fi

    CONTAINER_NAME="package-verify-$PACKAGE_TEST-$TARGET"

    # Cope with needing --ignore for podman but not for docker
    "${CONTAINER_RUNTIME}" rm --force --ignore --volumes "$CONTAINER_NAME" || "${CONTAINER_RUNTIME}" rm --force --volumes "$CONTAINER_NAME"

    # We do want splitting for build args
    # shellcheck disable=SC2086
    "${CONTAINER_RUNTIME}" build \
                --build-arg STAGING_KEY=$STAGING_KEY \
                --build-arg STAGING_URL=$STAGING_URL \
                --build-arg RELEASE_KEY=$RELEASE_KEY \
                --build-arg RELEASE_URL=$RELEASE_URL $BUILD_ARGS \
                --target "$TARGET" \
                -t "$CONTAINER_NAME" \
                -f "$SCRIPT_DIR/Dockerfile.$PACKAGE_TEST" "$SCRIPT_DIR/"

    if [[ "$CONTAINER_RUNTIME" == "docker" ]]; then
        "${CONTAINER_RUNTIME}" run --rm -d \
            --privileged \
            -v /sys/fs/cgroup/:/sys/fs/cgroup:ro \
            --name "$CONTAINER_NAME" \
            "$CONTAINER_NAME"
    else
        "${CONTAINER_RUNTIME}" run --rm -d \
            --timeout 30 \
            --name "$CONTAINER_NAME" \
            "$CONTAINER_NAME"
    fi

    "${CONTAINER_RUNTIME}" exec -t "$CONTAINER_NAME" /test.sh

    "${CONTAINER_RUNTIME}" rm --force --ignore --volumes "$CONTAINER_NAME" || "${CONTAINER_RUNTIME}" rm --force --volumes "$CONTAINER_NAME"
done
