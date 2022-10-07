#!/bin/bash
#
# Verifies RPM and DEB packages from Confluent Platform
#

cpver=$1
base_url=$2

if [[ -z $base_url ]]; then
    echo "Usage: $0 <CP-M.m-version> <base-url>"
    echo ""
    echo " <CP-M.m-version> is the Major.minor version of CP, e.g., 5.3"
    echo " <base-url> is the release base bucket URL"
    exit 1
fi

thisdir="$( cd "$(dirname "$0")" ; pwd -P )"

echo "#### Verifying RPM packages ####"
docker run -v $thisdir:/v centos:7 /v/verify-rpm.sh $cpver $base_url
rpm_status=$?

echo "#### Verifying Debian packages ####"
docker run -v $thisdir:/v ubuntu:16.04 /v/verify-deb.sh $cpver $base_url
deb_status=$?


if [[ $rpm_status == 0 ]]; then
    echo "SUCCESS: RPM packages verified"
else
    echo "ERROR: RPM package verification failed"
fi

if [[ $deb_status == 0 ]]; then
    echo "SUCCESS: Debian packages verified"
else
    echo "ERROR: Debian package verification failed"
fi

if [[ $deb_status != 0 || $rpm_status != 0 ]]; then
    exit 1
fi

