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

# Simple smoke test script of each local container architecture that runs up and then
# ensure we can access the web server.

CONTAINER_NAME=${CONTAINER_NAME:-smoke-test}

# Ensure the container name is valid as we need this to retrieve the exposed ports.
CONTAINER_NAME=${CONTAINER_NAME//\//-}
CONTAINER_ARCH=${CONTAINER_ARCH:-linux/amd64}
REGISTRY=${REGISTRY:-ghcr.io}
IMAGE_NAME=${IMAGE_NAME:-fluent/fluent-bit}
IMAGE_TAG=${IMAGE_TAG:-latest}

# Remove any existing container
docker rm -f "$CONTAINER_NAME"

# Repeat for YAML and legacy config - note the config file extension is important for format detection
declare -a CONFIG_FILES=("fluent-bit.conf" "fluent-bit.yaml")

for CONFIG_FILE in "${CONFIG_FILES[@]}"
do
    if [[ ! -f "$SCRIPT_DIR/$CONFIG_FILE" ]]; then
        echo "Missing config file: $SCRIPT_DIR/$CONFIG_FILE"
        exit 1
    fi

    echo "Testing: $CONFIG_FILE"

    # Run up the container
    docker run --name "$CONTAINER_NAME" -d \
        --platform "$CONTAINER_ARCH" \
        --pull=always \
        --publish-all \
        --restart=no \
        -v "$SCRIPT_DIR/$CONFIG_FILE":"/fluent-bit/etc/$CONFIG_FILE":ro \
        "$REGISTRY/$IMAGE_NAME:$IMAGE_TAG" \
        "/fluent-bit/bin/fluent-bit" "-c" "/fluent-bit/etc/$CONFIG_FILE"

    # Get debug details
    docker image inspect "$REGISTRY/$IMAGE_NAME:$IMAGE_TAG"

    # Stream the logs live
    docker logs -f "$CONTAINER_NAME" &

    # # Wait for the container to start up as we have to pull it
    until [[ $(docker ps --filter "status=running" --filter "name=$CONTAINER_NAME" --quiet | wc -l) -gt 0 ]] ; do
        sleep 2
    done
    docker ps
    # Grab the ephemeral port
    docker container inspect "$CONTAINER_NAME"
    LOCAL_PORT=$(docker inspect --format='{{(index (index .NetworkSettings.Ports "2020/tcp") 0).HostPort}}' "$CONTAINER_NAME")
    # Allow to run for a bit
    sleep 60
    docker ps
    docker logs "$CONTAINER_NAME"
    # Check we are still ok
    curl -v localhost:"$LOCAL_PORT"                 | jq
    curl -v localhost:"$LOCAL_PORT"/api/v1/metrics  | jq
    curl -v localhost:"$LOCAL_PORT"/api/v1/uptime   | jq
    curl -v localhost:"$LOCAL_PORT"/api/v1/health

    # Clean up
    docker rm -f "$CONTAINER_NAME"
done
