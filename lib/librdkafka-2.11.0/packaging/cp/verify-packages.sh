#!/bin/bash
#
# Verifies RPM and DEB packages from Confluent Platform
#
base_url=$1
platform=$2
version=$3

if [[ -z $base_url || -z $version ]]; then
    echo "Usage: $0 <base-url> <platform> <version>"
    echo ""
    echo " <base-url> is the release base bucket URL"
    echo " <platform> is platform to verify (e.g. linux/amd64)"
    echo " <version> is the expected version"
    exit 1
fi

thisdir="$( cd "$(dirname "$0")" ; pwd -P )"

verify_debian() {
    local version=$2
    docker run -v $thisdir:/v $1 /v/verify-deb.sh $base_url $version
    deb_status=$?
    if [[ $deb_status == 0 ]]; then
        echo "SUCCESS: Debian based $1 $2 packages verified"
    else
        echo "ERROR: Debian based $1 $2 package verification failed"
        exit 1
    fi
}

verify_rpm() {
    local version=$2
    docker run -v $thisdir:/v $1 /v/verify-rpm.sh $base_url $version
    rpm_status=$?
    if [[ $rpm_status == 0 ]]; then
        echo "SUCCESS: RPM $1 $2 packages verified"
    else
        echo "ERROR: RPM $1 $2 package verification failed"
        exit 1
    fi
}

verify_rpm_distros() {
    local platform=$1
    local version=$2
    echo "#### Verifying RPM packages for $platform ####"
    # Last RHEL 8 version is 2.4.0
    verify_rpm rockylinux:8 "2.4.0"
    verify_rpm rockylinux:9 $version
}

verify_debian_distros() {
    local platform=$1
    local version=$2
    echo "#### Verifying Debian packages for $platform ####"
    # Last Debian 10 version is 2.5.0
    verify_debian debian:10 "2.5.0"
    verify_debian debian:11 $version
    verify_debian debian:12 $version
    verify_debian ubuntu:20.04 $version
    verify_debian ubuntu:22.04 $version
    verify_debian ubuntu:24.04 $version
}

verify_distros() {
    verify_rpm_distros $1 $2
    verify_debian_distros $1 $2
}

verify_distros $platform $version
