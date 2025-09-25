#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

function usage() {
    echo "Usage: $0 2.1.2"
    echo "Or set NEW_VERSION=2.1.2"
}

function sed_wrapper() {
  if sed --version >/dev/null 2>&1; then
    $(which sed) "$@"
  else
    if command -v gsed >/dev/null 2>&1 ; then
      # homebrew gnu-sed is required on MacOS
      gsed "$@"
    else
      echo "ERROR: No valid GNU compatible 'sed' found, if on macOS please run 'brew install gnu-sed'" >&2
      exit 1
    fi
  fi
}

NEW_VERSION=${NEW_VERSION:-$1}

if [[ -z "$NEW_VERSION" ]]; then
    usage
    exit 1
fi

# Handle stripping the v prefix if present
if [[ "$NEW_VERSION" =~ ^v?([0-9]+\.[0-9]+\.[0-9]+)$ ]] ; then
    NEW_VERSION=${BASH_REMATCH[1]}
    echo "Valid version string: $NEW_VERSION"
else
    echo "ERROR: Invalid semver string: $NEW_VERSION" >&2
    exit 1
fi

# Get the current year
NEW_COPYRIGHT_YEAR=${NEW_COPYRIGHT_YEAR:-$(date +%Y)}

# Update Copyright statement
sed_wrapper -i -E "s/Copyright \(C\) 2015-([0-9]+)/Copyright (C) 2015-$NEW_COPYRIGHT_YEAR/g" "$SCRIPT_DIR"/include/fluent-bit/flb_version.h.in

# Extract and verify each version
major=$(echo "$NEW_VERSION" | cut -d. -f1)
minor=$(echo "$NEW_VERSION" | cut -d. -f2)
patch=$(echo "$NEW_VERSION" | cut -d. -f3)

if [[ -z "$major" ]]; then
    echo "ERROR: major is empty, invalid version: $NEW_VERSION" >&2
    exit 1
fi
if [[ -z "$minor" ]]; then
    echo "ERROR: minor is empty, invalid version: $NEW_VERSION" >&2
    exit 1
fi
if [[ -z "$patch" ]]; then
    echo "ERROR: patch is empty, invalid version: $NEW_VERSION" >&2
    exit 1
fi

# Build version
sed_wrapper -i -E "s/(FLB_VERSION_MAJOR[[:space:]]+)[0-9]+/\1$major/g" "$SCRIPT_DIR"/CMakeLists.txt
sed_wrapper -i -E "s/(FLB_VERSION_MINOR[[:space:]]+)[0-9]+/\1$minor/g" "$SCRIPT_DIR"/CMakeLists.txt
sed_wrapper -i -E "s/(FLB_VERSION_PATCH[[:space:]]+)[0-9]+/\1$patch/g" "$SCRIPT_DIR"/CMakeLists.txt

# Dockerfile
sed_wrapper -i -E "s/(ARG RELEASE_VERSION=)[0-9]+\.[0-9]+\.[0-9]+/\1$NEW_VERSION/g" "$SCRIPT_DIR"/dockerfiles/Dockerfile
sed_wrapper -i -E "s/(ARG RELEASE_VERSION=)[0-9]+\.[0-9]+\.[0-9]+/\1$NEW_VERSION/g" "$SCRIPT_DIR"/dockerfiles/Dockerfile*


# Snap
sed_wrapper -i -E "s/version: '[0-9]+\.[0-9]+\.[0-9]+'/version: '$NEW_VERSION'/g" "$SCRIPT_DIR"/snap/snapcraft.yaml

# Bitbake / Yocto
if [[ -f "$SCRIPT_DIR/fluent-bit-$NEW_VERSION.bb" ]]; then
    echo "ERROR: existing fluent-bit-$NEW_VERSION.bb"
    exit 1
else
    old_bb=$(find "$SCRIPT_DIR" -maxdepth 1 -type f -name 'fluent-bit-[0-9]*.[0-9]*.[0-9]*.bb' | head -n1)
    if [[ -z "$old_bb" ]]; then
        echo "ERROR: no existing .bb file found" >&2
        exit 1
    fi
    mv -vf "$old_bb" "$SCRIPT_DIR/fluent-bit-$NEW_VERSION.bb"
    sed_wrapper -i -E \
      "s/^PV *= *\"?[0-9]+\.[0-9]+\.[0-9]+\"?/PV = \"$NEW_VERSION\"/g" \
      "$SCRIPT_DIR/fluent-bit-$NEW_VERSION.bb"
fi

if [[ "${DISABLE_COMMIT:-no}" == "no" ]]; then
    if ! command -v git &> /dev/null ; then
        echo "ERROR: Missing git CLI" >&2
        exit 1
    fi

    git commit -s -m "build: bump to v$NEW_VERSION" -- CMakeLists.txt
    git commit -s -m "dockerfile: bump to v$NEW_VERSION" -- dockerfiles/*
    git commit -s -m "snap: bump to v$NEW_VERSION" snap/snapcraft.yaml
    # Handle renaming
    git add "*.bb"
    git commit -a -s -m "bitbake: bump to v$NEW_VERSION"
else
    echo "Skipping commits"
fi

echo "Updated version successfully"
