#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GENERATOR="$REPO_ROOT/packaging/generate-packages-index.sh"
OUTPUT_DIR="$(mktemp -d)"
S3_LISTING_FILE=""

cleanup()
{
    rm -rf "$OUTPUT_DIR" "${OUTPUT_DIR_S3:-}" "${OUTPUT_DIR_OVERRIDE:-}" \
        "${EMPTY_BASE_PATH:-}" "$S3_LISTING_FILE"
}

trap cleanup EXIT

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required to run this test" >&2
    exit 1
fi

if ! command -v tree >/dev/null 2>&1; then
    echo "ERROR: tree is required to run this test" >&2
    exit 1
fi

setup_local_fixture()
{
    local root="$1"

    mkdir -p \
        "$root/4.2.7" \
        "$root/centos/9" \
        "$root/macos" \
        "$root/windows" \
        "$root/ubuntu/jammy/pool/main/f/fluent-bit"

    touch \
        "$root/4.2.7/fluent-bit-schema-4.2.7.json" \
        "$root/centos/9/fluent-bit-4.2.6-1.x86_64.rpm" \
        "$root/centos/9/fluent-bit-4.2.7-1.x86_64.rpm" \
        "$root/macos/fluent-bit-4.2.7.pkg" \
        "$root/ubuntu/jammy/pool/main/f/fluent-bit/fluent-bit_4.2.6_amd64.deb" \
        "$root/ubuntu/jammy/pool/main/f/fluent-bit/fluent-bit_4.2.7_amd64.deb" \
        "$root/windows/fluent-bit-4.2.6-win64.exe" \
        "$root/windows/fluent-bit-4.2.7-win64.exe" \
        "$root/windows/fluent-bit-4.2.7-win64.zip"
}

setup_s3_listing_fixture()
{
    S3_LISTING_FILE="$(mktemp)"
    cat > "$S3_LISTING_FILE" <<'EOF'
4.2.7/fluent-bit-schema-4.2.7.json
centos/9/fluent-bit-4.2.6-1.x86_64.rpm
centos/9/fluent-bit-4.2.7-1.x86_64.rpm
macos/fluent-bit-4.2.7.pkg
ubuntu/jammy/pool/main/f/fluent-bit/fluent-bit_4.2.6_amd64.deb
ubuntu/jammy/pool/main/f/fluent-bit/fluent-bit_4.2.7_amd64.deb
windows/fluent-bit-4.2.6-win64.exe
windows/fluent-bit-4.2.7-win64.exe
windows/fluent-bit-4.2.7-win64.zip
EOF
}

assert_contains()
{
    local file="$1"
    local needle="$2"

    if ! grep -Fq "$needle" "$file"; then
        echo "ERROR: expected to find '$needle' in $file" >&2
        exit 1
    fi
}

assert_equals()
{
    local file="$1"
    local expected="$2"
    local actual

    actual="$(<"$file")"
    if [[ "$actual" != "$expected" ]]; then
        echo "ERROR: expected '$expected' in $file, got '$actual'" >&2
        exit 1
    fi
}

assert_fails_with()
{
    local expected_msg="$1"
    shift
    local output=""

    if output=$("$@" 2>&1); then
        echo "ERROR: expected command to fail: $*" >&2
        exit 1
    fi

    if [[ -n "$expected_msg" ]] && ! grep -Fq "$expected_msg" <<< "$output"; then
        echo "ERROR: expected error message '$expected_msg', got: $output" >&2
        exit 1
    fi
}

assert_versions_json_match()
{
    local left="$1"
    local right="$2"

    if ! diff <(jq -S 'del(.generated_at)' "$left") \
              <(jq -S 'del(.generated_at)' "$right") >/dev/null; then
        echo "ERROR: versions.json mismatch between $left and $right" >&2
        diff -u <(jq -S 'del(.generated_at)' "$left") \
                <(jq -S 'del(.generated_at)' "$right") >&2 || true
        exit 1
    fi
}

setup_local_fixture "$OUTPUT_DIR"

BASE_PATH="$OUTPUT_DIR" \
AWS_S3_REMOTE_DISCOVERY=false \
BASE_URL=https://packages.example.test \
"$GENERATOR"

assert_equals "$OUTPUT_DIR/latest-version.txt" "4.2.7"
assert_contains "$OUTPUT_DIR/index.html" "Latest release: <strong>4.2.7</strong>"
assert_contains "$OUTPUT_DIR/index.html" "4.2.6"
assert_contains "$OUTPUT_DIR/index.html" "fluent-bit-4.2.7-win64.exe"
assert_contains "$OUTPUT_DIR/index.html" "https://packages.example.test/versions.json"

if ! jq -e '.latest == "4.2.7" and (.versions | length) == 2' "$OUTPUT_DIR/versions.json" >/dev/null; then
    echo "ERROR: versions.json did not contain the expected version entries" >&2
    jq . "$OUTPUT_DIR/versions.json" >&2 || true
    exit 1
fi

if ! jq -e '.versions[] | select(.version == "4.2.7") | .artifacts.linux[] | select(.label == "centos/9 x86_64 rpm")' \
    "$OUTPUT_DIR/versions.json" >/dev/null; then
    echo "ERROR: versions.json missing Linux RPM artifact for 4.2.7" >&2
    exit 1
fi

if ! jq -e '.versions[] | select(.version == "4.2.7") | .artifacts.linux[] | select(.label == "ubuntu/jammy amd64 deb")' \
    "$OUTPUT_DIR/versions.json" >/dev/null; then
    echo "ERROR: versions.json missing Linux DEB artifact for 4.2.7" >&2
    exit 1
fi

if ! jq -e '.versions[] | select(.version == "4.2.7") | .artifacts.windows.win64_exe' \
    "$OUTPUT_DIR/versions.json" >/dev/null; then
    echo "ERROR: versions.json missing Windows artifact for 4.2.7" >&2
    exit 1
fi

if ! jq -e '.versions[] | select(.version == "4.2.7") | .artifacts.macos.pkg' \
    "$OUTPUT_DIR/versions.json" >/dev/null; then
    echo "ERROR: versions.json missing macOS pkg artifact for 4.2.7" >&2
    exit 1
fi

echo "packages-index generator test passed"

OUTPUT_DIR_S3="$(mktemp -d)"
setup_s3_listing_fixture

BASE_PATH="$OUTPUT_DIR_S3" \
BASE_URL=https://packages.example.test \
AWS_S3_BUCKET=packages.example.test \
AWS_S3_REMOTE_DISCOVERY=true \
AWS_S3_LISTING_FILE="$S3_LISTING_FILE" \
"$GENERATOR"

assert_equals "$OUTPUT_DIR_S3/latest-version.txt" "4.2.7"
assert_contains "$OUTPUT_DIR_S3/index.html" "fluent-bit-4.2.7-win64.exe"
assert_versions_json_match "$OUTPUT_DIR/versions.json" "$OUTPUT_DIR_S3/versions.json"

if ! jq -e '.latest == "4.2.7" and .base_url == "https://packages.example.test" and (.versions | length) == 2' \
    "$OUTPUT_DIR_S3/versions.json" >/dev/null; then
    echo "ERROR: S3 listing parse did not produce expected catalog metadata" >&2
    jq . "$OUTPUT_DIR_S3/versions.json" >&2 || true
    exit 1
fi

echo "packages-index S3 listing parse test passed"

OUTPUT_DIR_OVERRIDE="$(mktemp -d)"
setup_local_fixture "$OUTPUT_DIR_OVERRIDE"

BASE_PATH="$OUTPUT_DIR_OVERRIDE" \
AWS_S3_REMOTE_DISCOVERY=false \
LATEST_VERSION=4.2.6 \
BASE_URL=https://packages.example.test \
"$GENERATOR"

assert_equals "$OUTPUT_DIR_OVERRIDE/latest-version.txt" "4.2.6"
if ! jq -e '.latest == "4.2.6"' "$OUTPUT_DIR_OVERRIDE/versions.json" >/dev/null; then
    echo "ERROR: LATEST_VERSION override did not update latest field" >&2
    exit 1
fi

assert_fails_with "LATEST_VERSION '9.9.9' was not found among discovered versions" \
    env BASE_PATH="$OUTPUT_DIR" AWS_S3_REMOTE_DISCOVERY=false LATEST_VERSION=9.9.9 \
    BASE_URL=https://packages.example.test "$GENERATOR"

EMPTY_BASE_PATH="$(mktemp -d)"
assert_fails_with "ERROR: no objects found under" \
    env BASE_PATH="$EMPTY_BASE_PATH" AWS_S3_REMOTE_DISCOVERY=false \
    BASE_URL=https://packages.example.test "$GENERATOR"

assert_fails_with "AWS_S3_LISTING_FILE does not exist" \
    env BASE_PATH="$OUTPUT_DIR_S3" AWS_S3_REMOTE_DISCOVERY=true \
    AWS_S3_BUCKET=packages.example.test \
    AWS_S3_LISTING_FILE=/tmp/does-not-exist-packages-index-test \
    BASE_URL=https://packages.example.test "$GENERATOR"

echo "packages-index validation error handling test passed"

PREVIEW_SCRIPT="$SCRIPT_DIR/generate-preview-from-s3.sh"
PREVIEW_DIR="$SCRIPT_DIR/preview"

bash -n "$PREVIEW_SCRIPT"

AWS_S3_LISTING_FILE="$S3_LISTING_FILE" \
AWS_S3_BUCKET=packages.example.test \
"$PREVIEW_SCRIPT"

test -f "$PREVIEW_DIR/index.html"
assert_equals "$PREVIEW_DIR/latest-version.txt" "4.2.7"
if ! jq -e '.latest == "4.2.7"' "$PREVIEW_DIR/versions.json" >/dev/null; then
    echo "ERROR: preview versions.json did not identify 4.2.7 as latest" >&2
    jq . "$PREVIEW_DIR/versions.json" >&2 || true
    exit 1
fi

echo "packages-index preview script test passed"
