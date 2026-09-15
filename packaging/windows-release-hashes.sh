#!/bin/bash
set -euo pipefail

# Usage: windows-release-hashes.sh VERSION [CHECKSUM_DIRECTORY]
# Validate Windows release manifests and print NAME=hash records to stdout.
# Diagnostics go to stderr so stdout can be appended to GITHUB_OUTPUT or reused
# outside GitHub Actions. ARM64 is optional for older releases.

RELEASE_VERSION=${1:?Usage: windows-release-hashes.sh VERSION [CHECKSUM_DIRECTORY]}
SOURCE_DIR=${2:-.}

write_hash()
{
    local output_name="$1"
    local package="fluent-bit-${RELEASE_VERSION}-$2"
    local filename="$package.sha256"
    local hash

    if ! hash=$(awk -v package="$package" '
      {
        valid = (length($1) == 64 && $1 ~ /^[[:xdigit:]]+$/ &&
                 (substr($0, 65, 2) == "  " || substr($0, 65, 2) == " *") &&
                 substr($0, 67) == package)
      }
      END {
        if (NR != 1 || !valid) {
          exit 1
        }
        print $1
      }
    ' "$filename"); then
        echo "ERROR: Expected exactly one SHA-256 record for $package in $filename" >&2
        exit 1
    fi
    echo "$output_name=$hash"
}

cd "$SOURCE_DIR"

write_hash WIN_32_EXE_HASH win32.exe
write_hash WIN_32_ZIP_HASH win32.zip
write_hash WIN_64_EXE_HASH win64.exe
write_hash WIN_64_ZIP_HASH win64.zip
if compgen -G "fluent-bit-${RELEASE_VERSION}-winarm64.*.sha256" > /dev/null; then
    write_hash WIN_64_ARM_EXE_HASH winarm64.exe
    write_hash WIN_64_ARM_ZIP_HASH winarm64.zip
fi
