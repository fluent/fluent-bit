#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

BASE_PATH=${BASE_PATH:-${1:-}}
BASE_URL=${BASE_URL:-https://packages.fluentbit.io}
LATEST_VERSION=${LATEST_VERSION:-}
GITHUB_REPO=${GITHUB_REPO:-https://github.com/fluent/fluent-bit}
DOCS_URL=${DOCS_URL:-https://docs.fluentbit.io/manual/installation}
AWS_S3_BUCKET=${AWS_S3_BUCKET:-}
AWS_S3_REMOTE_DISCOVERY=${AWS_S3_REMOTE_DISCOVERY:-false}
AWS_S3_NO_SIGN_REQUEST=${AWS_S3_NO_SIGN_REQUEST:-true}
AWS_S3_ENDPOINT=${AWS_S3_ENDPOINT:-}

WORK_DIR=""
OBJECT_LIST=""

LINUX_REPO_PATHS=(
    "amazonlinux/2"
    "amazonlinux/2023"
    "centos/7"
    "centos/8"
    "centos/9"
    "centos/10"
    "rockylinux/8"
    "rockylinux/9"
    "rockylinux/10"
    "almalinux/8"
    "almalinux/9"
    "almalinux/10"
    "debian/bookworm"
    "debian/bullseye"
    "debian/buster"
    "debian/trixie"
    "ubuntu/jammy"
    "ubuntu/noble"
    "ubuntu/resolute"
    "raspbian/bookworm"
)

usage()
{
    cat <<EOF
Usage: $(basename "$0") [BASE_PATH]

Generate index.html, versions.json, and latest-version.txt for packages.fluentbit.io.

Environment variables:
  BASE_PATH               Local output/mirror directory (required)
  BASE_URL                Public URL prefix for links (default: https://packages.fluentbit.io)
  LATEST_VERSION          Override latest version (default: highest version found)
  AWS_S3_BUCKET           S3 bucket name for remote discovery (optional)
  AWS_S3_REMOTE_DISCOVERY Set to true to list versions/artifacts from S3
  AWS_S3_LISTING_FILE     Use a pre-fetched S3 listing instead of calling aws
  AWS_S3_NO_SIGN_REQUEST  Use anonymous S3 access (default: true)
  AWS_S3_ENDPOINT         Optional custom S3 endpoint URL
  GITHUB_REPO             GitHub repository URL for release links
  DOCS_URL                Installation documentation URL

Example:
  BASE_PATH=./catalog ./generate-packages-index.sh

  AWS_S3_BUCKET=packages.fluentbit.io AWS_S3_REMOTE_DISCOVERY=true \\
    BASE_PATH=./catalog ./generate-packages-index.sh
EOF
}

cleanup()
{
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}

if [[ -z "$BASE_PATH" || "$BASE_PATH" == "-h" || "$BASE_PATH" == "--help" ]]; then
    usage
    if [[ -z "$BASE_PATH" ]]; then
        exit 1
    fi
    exit 0
fi

if [[ ! -d "$BASE_PATH" ]]; then
    echo "ERROR: BASE_PATH is not a directory: $BASE_PATH" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 1
fi

if ! command -v tree >/dev/null 2>&1; then
    echo "ERROR: tree is required" >&2
    exit 1
fi

BASE_PATH="$(cd "$BASE_PATH" && pwd)"
WORK_DIR="$(mktemp -d)"
OBJECT_LIST="$WORK_DIR/objects.txt"
TREE_LIST="$WORK_DIR/tree.txt"
VERSION_ROWS="$WORK_DIR/version-rows.tsv"
trap cleanup EXIT

aws_s3_listing_cmd()
{
    local -a cmd=(aws s3 ls "s3://${AWS_S3_BUCKET}/" --recursive)

    if [[ "$AWS_S3_NO_SIGN_REQUEST" == "true" ]]; then
        cmd+=(--no-sign-request)
    fi
    if [[ -n "$AWS_S3_ENDPOINT" ]]; then
        cmd+=(--endpoint-url "$AWS_S3_ENDPOINT")
    fi

    "${cmd[@]}"
}

s3_listing_relative_path()
{
    awk 'NF >= 4 {
        $1 = ""
        $2 = ""
        $3 = ""
        sub(/^ +/, "")
        print
    }'
}

collect_local_objects()
{
    local file base

    while IFS= read -r -d '' file; do
        base="$(basename "$file")"
        case "$base" in
            index.html|versions.json|latest-version.txt)
                continue
                ;;
        esac
        echo "${file#"$BASE_PATH"/}"
    done < <(find "$BASE_PATH" -type f -print0 2>/dev/null || true)
}

collect_s3_objects()
{
    local destination="$1"

    if [[ -n "${AWS_S3_LISTING_FILE:-}" ]]; then
        if [[ ! -f "$AWS_S3_LISTING_FILE" ]]; then
            echo "ERROR: AWS_S3_LISTING_FILE does not exist: $AWS_S3_LISTING_FILE" >&2
            exit 1
        fi
        cp "$AWS_S3_LISTING_FILE" "$destination"
        return 0
    fi

    if ! command -v aws >/dev/null 2>&1; then
        echo "ERROR: aws CLI is required for AWS_S3_REMOTE_DISCOVERY" >&2
        exit 1
    fi

    aws_s3_listing_cmd | s3_listing_relative_path > "$destination"
}

build_object_list()
{
    : > "$OBJECT_LIST"
    collect_local_objects >> "$OBJECT_LIST"

    if [[ "$AWS_S3_REMOTE_DISCOVERY" == "true" ]]; then
        if [[ -z "$AWS_S3_BUCKET" && -z "${AWS_S3_LISTING_FILE:-}" ]]; then
            echo "ERROR: AWS_S3_BUCKET or AWS_S3_LISTING_FILE is required for remote discovery" >&2
            exit 1
        fi

        collect_s3_objects "$WORK_DIR/s3-listing.txt"
        echo "Fetched $(wc -l < "$WORK_DIR/s3-listing.txt" | tr -d ' ') objects from s3://${AWS_S3_BUCKET:-listing}" >&2
        cat "$WORK_DIR/s3-listing.txt" >> "$OBJECT_LIST"
    fi

    sort -u -o "$OBJECT_LIST" "$OBJECT_LIST"
}

render_index_html()
{
    local latest="$1"
    local generated_at="$2"
    local tree_html="$3"

    sed "s|<body>|<body><h1>Fluent Bit Packages</h1><p>Latest release: <strong>${latest}</strong><br>Generated: ${generated_at}<br>Catalog: <a href=\"${BASE_URL}/versions.json\">versions.json</a>, <a href=\"${BASE_URL}/latest-version.txt\">latest-version.txt</a>, <a href=\"${BASE_URL}/fluentbit.key\">fluentbit.key</a></p>|" \
        "$tree_html" > "$BASE_PATH/index.html"
}

build_object_list

if [[ ! -s "$OBJECT_LIST" ]]; then
    echo "ERROR: no objects found under $BASE_PATH" >&2
    exit 1
fi

grep -Ev 'source-|pool|dists' "$OBJECT_LIST" | \
    grep -E '\.(rpm|deb|key|repo|exe|msi|zip|pkg)$' > "$TREE_LIST" || true

if [[ ! -s "$TREE_LIST" ]]; then
    echo "ERROR: no package files found for index.html" >&2
    exit 1
fi

tree --noreport --charset utf-8 --fromfile "$TREE_LIST" -H "$BASE_URL" | \
    awk '/<hr>/ { exit } { print } END { print "</body></html>" }' > "$WORK_DIR/tree.html"

REPO_PATHS="$(printf '%s ' "${LINUX_REPO_PATHS[@]}")"
awk -v emit_mode=versions \
    -v base_url="$BASE_URL" \
    -v github_release="$GITHUB_REPO" \
    -v docs_url="$DOCS_URL" \
    -v repo_paths="$REPO_PATHS" \
    -f "$SCRIPT_DIR/build-catalog.awk" \
    "$OBJECT_LIST" | sort -t $'\t' -V -k1,1 > "$VERSION_ROWS"

if [[ ! -s "$VERSION_ROWS" ]]; then
    echo "ERROR: no Fluent Bit package versions found" >&2
    exit 1
fi

SORTED_VERSIONS=()
while IFS= read -r version; do
    SORTED_VERSIONS+=("$version")
done < <(awk -F '\t' '{ print $1 }' "$VERSION_ROWS")

if [[ -n "$LATEST_VERSION" ]]; then
    found=0
    for version in "${SORTED_VERSIONS[@]}"; do
        if [[ "$version" == "$LATEST_VERSION" ]]; then
            found=1
            break
        fi
    done
    if [[ "$found" -eq 0 ]]; then
        echo "ERROR: LATEST_VERSION '$LATEST_VERSION' was not found among discovered versions: ${SORTED_VERSIONS[*]}" >&2
        exit 1
    fi
    LATEST="$LATEST_VERSION"
else
    LATEST="${SORTED_VERSIONS[${#SORTED_VERSIONS[@]}-1]}"
fi

GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

jq -n \
    --arg latest "$LATEST" \
    --arg generated_at "$GENERATED_AT" \
    --arg base_url "$BASE_URL" \
    --argjson versions "$(awk -F '\t' '{ print $2 }' "$VERSION_ROWS" | jq -s 'reverse')" \
    '{
        latest: $latest,
        generated_at: $generated_at,
        base_url: $base_url,
        versions: $versions
    }' > "$BASE_PATH/versions.json"

printf '%s\n' "$LATEST" > "$BASE_PATH/latest-version.txt"
render_index_html "$LATEST" "$GENERATED_AT" "$WORK_DIR/tree.html"

echo "Generated:"
echo "  $BASE_PATH/index.html"
echo "  $BASE_PATH/versions.json"
echo "  $BASE_PATH/latest-version.txt"
echo "Latest version: $LATEST"
echo "Discovered versions (${#SORTED_VERSIONS[@]}): $(printf '%s ' "${SORTED_VERSIONS[@]}")"
