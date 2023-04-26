#!/bin/bash
set -eux

NEW_VERSION=${NEW_VERSION:-$1}

if [[ -z "$NEW_VERSION" ]]; then
    echo "Usage: $0 2.1.2" >&2
    exit 1
fi

# Handle stripping the v prefix if present
if [[ "$NEW_VERSION" =~ ^v?([0-9]+\.[0-9]+\.[0-9]+)$ ]] ; then
    NEW_VERSION=${BASH_REMATCH[1]}
    echo "Valid version string: $NEW_VERSION"
else
    echo "ERROR: Invalid semver string: $NEW_VERSION"
    exit 1
fi

# Extract and verify each version
major=$(echo "$NEW_VERSION" | cut -d. -f1)
minor=$(echo "$NEW_VERSION" | cut -d. -f2)
minor=$(echo "$NEW_VERSION" | cut -d. -f3)

if [[ -z "$major" ]]; then
    echo "ERROR: major is empty, invalid version: $NEW_VERSION"
    exit 1
fi
if [[ -z "$minor" ]]; then
    echo "ERROR: minor is empty, invalid version: $NEW_VERSION"
    exit 1
fi
if [[ -z "$patch" ]]; then
    echo "ERROR: patch is empty, invalid version: $NEW_VERSION"
    exit 1
fi

# Build version
sed -i "s/FLB_VERSION_MAJOR  [0-9]/FLB_VERSION_MAJOR  $major/g" CMakeLists.txt
sed -i "s/FLB_VERSION_MINOR  [0-9]/FLB_VERSION_MINOR  $minor/g" CMakeLists.txt
sed -i "s/FLB_VERSION_PATCH  [0-9]/FLB_VERSION_PATCH  $patch/g" CMakeLists.txt

git commit -s -m "build: bump to v$NEW_VERSION" -- CMakeLists.txt

# Dockerfile
sed -i "s/ARG RELEASE_VERSION=[0-9].[0-9].[0-9]/ARG RELEASE_VERSION=$NEW_VERSION/g" dockerfiles/Dockerfile
sed -i "s/ARG RELEASE_VERSION=[0-9].[0-9].[0-9]/ARG RELEASE_VERSION=$NEW_VERSION/g" dockerfiles/Dockerfile*

git commit -s -m "dockerfile: bump to v$NEW_VERSION" -- dockerfiles/*

# Snap
sed -i "s/version: '[0-9].[0-9].[0-9]'/version: '$NEW_VERSION'/g" snap/snapcraft.yaml
git commit -s -m "snap: bump to v$NEW_VERSION" snap/snapcraft.yaml

# Bitbake / Yocto
sed -i "s/PV = \"[0-9].[0-9].[0-9]\"/PV = \"$NEW_VERSION\"/g" fluent-bit_*.*.*.bb
git mv fluent-bit_*.*.*.bb "fluent-bit_$NEW_VERSION.bb"
git commit -a -s -m "bitbake: bump to v$NEW_VERSION"
