#!/bin/bash
#
# Automatically pushes a PR to homebrew-core to update
# the librdkafka version.
#
# Usage:
#   # Dry-run:
#   ./brew-update-pr.sh v0.11.0
#   # if everything looks good:
#   ./brew-update-pr.sh --upload v0.11.0
#


DRY_RUN="--dry-run"
if [[ $1 == "--upload" ]]; then
   DRY_RUN=
   shift
fi

TAG=$1

if [[ -z $TAG ]]; then
    echo "Usage: $0 [--upload] <librdkafka-tag>"
    exit 1
fi

set -eu

brew bump-formula-pr $DRY_RUN --strict \
     --url=https://github.com/edenhill/librdkafka/archive/${TAG}.tar.gz \
     librdkafka
