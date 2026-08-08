#!/usr/bin/env bash

set -euo pipefail

usage()
{
    cat <<EOF
Usage: $0 [VERSION]

Download and vendor the Databricks Zerobus SDK Rust FFI source.

Arguments:
  VERSION  Zerobus FFI release version to vendor. Defaults to 1.3.0.

Environment:
  ZEROBUS_SDK_ARCHIVE_URL   Override the full release archive URL.
  ZEROBUS_SDK_RELEASE_TAG   Override the GitHub release tag. Defaults to ffi/vVERSION.
  ZEROBUS_SDK_ARCHIVE_NAME  Override the archive filename.

Cargo registry configuration is intentionally not managed here. Use the normal
Cargo configuration mechanisms, such as CARGO_HOME/config.toml, when a registry
proxy is required.
EOF
}

die()
{
    echo "error: $*" >&2
    exit 1
}

need_command()
{
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

prune_workspace_members()
{
    local cargo_toml="$1"
    local cargo_toml_tmp="${cargo_toml}.tmp"

    awk '
        BEGIN { in_members = 0 }
        /^[[:space:]]*members[[:space:]]*=[[:space:]]*\[/ {
            print "members = ["
            print "    \"sdk\","
            print "    \"ffi\","
            print "]"
            in_members = 1
            next
        }
        in_members {
            if ($0 ~ /^[[:space:]]*\]/) {
                in_members = 0
            }
            next
        }
        { print }
    ' "$cargo_toml" > "$cargo_toml_tmp"

    mv "$cargo_toml_tmp" "$cargo_toml"
}

patch_ffi_build_rs()
{
    local build_rs="$1"

    perl -0pi -e \
        's/let output_file = PathBuf::from\(&crate_dir\)\.join\("zerobus\.h"\);/let output_file = PathBuf::from(env::var("OUT_DIR").unwrap()).join("zerobus.h");/' \
        "$build_rs"

    perl -0pi -e \
        's/\.write_to_file\(output_file\);/.write_to_file(\&output_file);/' \
        "$build_rs"

    grep -q 'env::var("OUT_DIR")' "$build_rs" ||
        die "failed to patch $build_rs to write cbindgen output under OUT_DIR"

    grep -q 'write_to_file(&output_file)' "$build_rs" ||
        die "failed to patch $build_rs to pass output_file by reference"
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -gt 1 ]; then
    usage
    exit 1
fi

for cmd in awk cargo curl find grep perl tar; do
    need_command "$cmd"
done

version="${1:-1.3.0}"
case "$version" in
    ""|*[!A-Za-z0-9._-]*)
        die "invalid version '${version}'; use characters from A-Z, a-z, 0-9, '.', '_' and '-'"
        ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest_dir="${repo_root}/lib/zerobus-ffi-${version}"
release_tag="${ZEROBUS_SDK_RELEASE_TAG:-ffi/v${version}}"
release_tag_escaped="${release_tag//\//%2F}"
archive_name="${ZEROBUS_SDK_ARCHIVE_NAME:-zerobus-ffi-${version}.tar.gz}"
archive_url="${ZEROBUS_SDK_ARCHIVE_URL:-https://github.com/databricks/zerobus-sdk/releases/download/${release_tag_escaped}/${archive_name}}"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/flb-zerobus-sdk.XXXXXX")"

cleanup()
{
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

archive_file="${tmp_dir}/${archive_name}"
extract_dir="${tmp_dir}/extract"
stage_dir="${tmp_dir}/zerobus-ffi-${version}"

echo "Downloading ${archive_url}"
curl -fL "$archive_url" -o "$archive_file"

mkdir -p "$extract_dir"
tar -xzf "$archive_file" -C "$extract_dir"

source_root="$(
    find "$extract_dir" -type f -path '*/rust/Cargo.toml' -print | while IFS= read -r cargo_toml; do
        candidate="${cargo_toml%/rust/Cargo.toml}"
        if [ -d "${candidate}/rust/ffi" ] && [ -d "${candidate}/rust/sdk" ]; then
            printf '%s\n' "$candidate"
            break
        fi
    done
)"

if [ -z "$source_root" ]; then
    die "could not find rust/Cargo.toml with rust/ffi and rust/sdk in archive"
fi

for path in \
    LICENSE \
    rust/Cargo.toml \
    rust/Cargo.lock \
    rust/LICENSE \
    rust/NOTICE \
    rust/README.md \
    rust/ffi \
    rust/sdk
do
    [ -e "${source_root}/${path}" ] || die "archive is missing ${path}"
done

mkdir -p "${stage_dir}/rust"
cp "${source_root}/LICENSE" "${stage_dir}/LICENSE"
cp "${source_root}/rust/Cargo.toml" "${stage_dir}/rust/Cargo.toml"
cp "${source_root}/rust/Cargo.lock" "${stage_dir}/rust/Cargo.lock"
cp "${source_root}/rust/LICENSE" "${stage_dir}/rust/LICENSE"
cp "${source_root}/rust/NOTICE" "${stage_dir}/rust/NOTICE"
cp "${source_root}/rust/README.md" "${stage_dir}/rust/README.md"
cp -R "${source_root}/rust/ffi" "${stage_dir}/rust/ffi"
cp -R "${source_root}/rust/sdk" "${stage_dir}/rust/sdk"

find "$stage_dir" -type d \( -name .git -o -name target \) -prune -exec rm -rf {} +
find "$stage_dir" -type f \( \
    -name '*.a' -o \
    -name '*.d' -o \
    -name '*.dylib' -o \
    -name '*.o' -o \
    -name '*.rlib' -o \
    -name '*.rmeta' -o \
    -name '*.so' \
\) -delete

prune_workspace_members "${stage_dir}/rust/Cargo.toml"
patch_ffi_build_rs "${stage_dir}/rust/ffi/build.rs"

(
    cd "${stage_dir}/rust"
    cargo metadata --no-deps --format-version 1 >/dev/null
    cargo metadata --locked --no-deps --format-version 1 >/dev/null
)

rm -rf "$dest_dir"
mv "$stage_dir" "$dest_dir"

echo "Vendored Zerobus FFI ${version} into ${dest_dir}"
