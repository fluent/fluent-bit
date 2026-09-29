#!/bin/bash
set -euo pipefail

# Usage: validate-windows-release-packages.sh VERSION [PACKAGE_DIRECTORY]
# Require nonempty Windows packages and exactly one matching checksum record
# per package, then verify the contents. ARM64 is optional for older releases.

RELEASE_VERSION=${1:?Usage: validate-windows-release-packages.sh VERSION [PACKAGE_DIRECTORY]}
SOURCE_DIR=${2:-.}

cd "$SOURCE_DIR"

architectures=(win32 win64)
if compgen -G "fluent-bit-${RELEASE_VERSION}-winarm64.*" > /dev/null; then
    architectures+=(winarm64)
fi
for arch in "${architectures[@]}"; do
    for extension in exe zip; do
        package="fluent-bit-${RELEASE_VERSION}-${arch}.${extension}"
        if [[ ! -s "$package" || ! -s "$package.sha256" ]]; then
            echo "ERROR: Missing Windows release artifact: $package or $package.sha256." >&2
            echo "Complete the Windows staging build/upload before releasing." >&2
            exit 1
        fi
        if ! awk -v package="$package" '
          {
            valid = (length($1) == 64 && $1 ~ /^[[:xdigit:]]+$/ &&
                     (substr($0, 65, 2) == "  " || substr($0, 65, 2) == " *") &&
                     substr($0, 67) == package)
          }
          END { exit !(NR == 1 && valid) }
        ' "$package.sha256"; then
            echo "ERROR: Expected exactly one SHA-256 record for $package in $package.sha256" >&2
            exit 1
        fi
        sha256sum --check --strict "$package.sha256"
    done
done
