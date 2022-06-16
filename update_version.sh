#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 1.7.0" >&2
    exit 1
fi

major=$(echo "$1" | sed -e "s/^\([0-9]*\)\.[0-9]*\.[0-9]*/\1/")
minor=$(echo "$1" | sed -e "s/^[0-9]*\.\([0-9]*\)\.[0-9]*/\1/")
patch=$(echo "$1" | sed -e "s/^[0-9]*\.[0-9]*\.\([0-9]*\)/\1/")

# Build version
sed -i "s/FLB_VERSION_MAJOR  [0-9]/FLB_VERSION_MAJOR  $major/g" CMakeLists.txt
sed -i "s/FLB_VERSION_MINOR  [0-9]/FLB_VERSION_MINOR  $minor/g" CMakeLists.txt
sed -i "s/FLB_VERSION_PATCH  [0-9]/FLB_VERSION_PATCH  $patch/g" CMakeLists.txt

git commit -s -m "build: bump to v$1" -- CMakeLists.txt

# Dockerfile
sed -i "s/ARG RELEASE_VERSION=[0-9].[0-9].[0-9]/ARG RELEASE_VERSION=$1/g" dockerfiles/Dockerfile*

git commit -s -m "dockerfile: bump to v$1" -- dockerfiles/*

# Snap
sed -i "s/version: '[0-9].[0-9].[0-9]'/version: '$1'/g" snap/snapcraft.yaml
git commit -s -m "snap: bump to v$1" snap/snapcraft.yaml

# Bitbake / Yocto
sed -i "s/PV = \"[0-9].[0-9].[0-9]\"/PV = \"$1\"/g" fluent-bit_*.*.*.bb
git mv fluent-bit_*.*.*.bb "fluent-bit_$1.bb"
git commit -a -s -m "bitbake: bump to v$1"
