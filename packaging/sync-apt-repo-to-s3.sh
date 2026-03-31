#!/bin/bash
set -euo pipefail

# Upload an APT repo in two phases so Release metadata only becomes visible
# after the referenced package indexes and pool files are already uploaded.

SOURCE_DIR=${1:?Usage: sync-apt-repo-to-s3.sh <source-dir> <s3-destination>}
DESTINATION=${2:?Usage: sync-apt-repo-to-s3.sh <source-dir> <s3-destination>}

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "ERROR: missing source dir: $SOURCE_DIR"
    exit 1
fi

SOURCE_DIR=$(realpath "$SOURCE_DIR")

aws s3 sync "$SOURCE_DIR" "$DESTINATION" \
    --delete \
    --follow-symlinks \
    --no-progress \
    --exclude "dists/*/InRelease" \
    --exclude "dists/*/Release" \
    --exclude "dists/*/Release.gpg"

DIST_DIR="$SOURCE_DIR/dists"
if [[ ! -d "$DIST_DIR" ]]; then
    echo "ERROR: missing dists dir in source: $DIST_DIR"
    exit 1
fi

while IFS= read -r metadata_file; do
    relative_path=${metadata_file#"$SOURCE_DIR"/}
    aws s3 cp "$metadata_file" "$DESTINATION/$relative_path" --no-progress
done < <(find "$DIST_DIR" -type f \( -name "InRelease" -o -name "Release" -o -name "Release.gpg" \) | sort)
