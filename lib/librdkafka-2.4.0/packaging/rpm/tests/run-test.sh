#!/bin/bash
#
# This script runs in the docker container, performing:
# * install build toolchain
# * install librdkafka rpms
# * builds test apps
# * runs test apps
#
# Usage: $0 <docker-image-name>

set -ex

pushd /v

_IMG=$1

echo "Testing on $_IMG"

if [[ $_IMG == "centos:6" ]]; then
    _EL=6
    _INST="yum install -y -q"
elif [[ $_IMG == "centos:7" ]]; then
    _EL=7
    _INST="yum install -y -q"
    # centos:7 ships with openssl-libs 1.0.1 which is outdated and not
    # ABI-compatible with 1.0.2 (which we build with).
    # Upgrade openssl-libs, as users would, to prevent missing symbols.
    _UPG="yum upgrade -y openssl-libs"
else
    _EL=8
    _INST="dnf install -y -q"
fi

$_INST gcc gcc-c++ make pkg-config

if [[ -n $_UPG ]]; then
    $_UPG
fi

$_INST /rpms/librdkafka1-*el${_EL}.x86_64.rpm /rpms/librdkafka-devel-*el${_EL}.x86_64.rpm

make clean all

make run

make clean

echo "$_IMG is all good!"

