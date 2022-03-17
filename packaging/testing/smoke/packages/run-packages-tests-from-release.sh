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

RELEASE_NAME=${RELEASE_NAME:-unstable-master}
RELEASE_PACKAGES=${RELEASE_PACKAGES:-packages-$RELEASE_NAME.tar.gz}
RELEASE_PACKAGES_URL=${RELEASE_PACKAGES_URL:-https://github.com/fluent/fluent-bit/releases/download/$RELEASE_NAME/$RELEASE_PACKAGES}
OUTPUT_DIR=${OUTPUT_DIR:-$SCRIPT_DIR/$RELEASE_NAME}

# Download tarball locally
rm -rf "${OUTPUT_DIR:?}/"
mkdir -p "$OUTPUT_DIR"
wget -O "$OUTPUT_DIR/$RELEASE_PACKAGES" "$RELEASE_PACKAGES_URL"
tar -xzvf "$OUTPUT_DIR/$RELEASE_PACKAGES" -C "$OUTPUT_DIR"

# Set up repo info
"$SCRIPT_DIR/../update-repos.sh" "master" "$OUTPUT_DIR"