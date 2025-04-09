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

if [[ $_IMG == "rockylinux:8" ]]; then
    _EL=8
    _INST="dnf install -y -q"
else
    _EL=9
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

