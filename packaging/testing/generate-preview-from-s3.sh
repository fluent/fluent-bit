#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PREVIEW_DIR="$SCRIPT_DIR/preview"
GENERATOR="$REPO_ROOT/packaging/generate-packages-index.sh"

mkdir -p "$PREVIEW_DIR"

if [[ -n "${AWS_S3_LISTING_FILE:-}" ]]; then
    echo "Using cached S3 listing: $AWS_S3_LISTING_FILE"
else
    echo "Discovering versions from s3://${AWS_S3_BUCKET:-packages.fluentbit.io} ..."
fi
echo "Writing preview to $PREVIEW_DIR"

BASE_PATH="$PREVIEW_DIR" \
AWS_S3_BUCKET="${AWS_S3_BUCKET:-packages.fluentbit.io}" \
AWS_S3_REMOTE_DISCOVERY=true \
AWS_S3_LISTING_FILE="${AWS_S3_LISTING_FILE:-}" \
AWS_S3_NO_SIGN_REQUEST="${AWS_S3_NO_SIGN_REQUEST:-true}" \
BASE_URL="${BASE_URL:-https://packages.fluentbit.io}" \
"$GENERATOR"

echo ""
echo "Open the generated page:"
echo "  $PREVIEW_DIR/index.html"
