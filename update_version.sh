#!/bin/sh
set -eux

NEW_VERSION=${NEW_VERSION:-$1}

if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 2.1.2" >&2
    exit 1
fi

major=$(echo "$NEW_VERSION" | sed -e "s/^\([0-9]*\)\.[0-9]*\.[0-9]*/\1/")
minor=$(echo "$NEW_VERSION" | sed -e "s/^[0-9]*\.\([0-9]*\)\.[0-9]*/\1/")
patch=$(echo "$NEW_VERSION" | sed -e "s/^[0-9]*\.[0-9]*\.\([0-9]*\)/\1/")

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
