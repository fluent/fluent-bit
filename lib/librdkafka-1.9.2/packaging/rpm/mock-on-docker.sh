#!/bin/bash
#
#
#
# Run mock in docker to create RPM packages of librdkafka.
#
# Usage:
#   packaging/rpm/mock-on-docker.sh [<mock configs ..>]
#

set -ex

_DOCKER_IMAGE=fedora:35
_MOCK_CONFIGS="centos+epel-7-x86_64 centos-stream+epel-8-x86_64"

if [[ $1 == "--build" ]]; then
    on_builder=1
    shift
else
    on_builder=0
fi


if [[ -n $* ]]; then
    _MOCK_CONFIGS="$*"
fi


if [[ $on_builder == 0 ]]; then
    #
    # Running on host, fire up a docker container and run the latter
    # part of this script in docker.
    #

    if [[ ! -f configure.self ]]; then
        echo "$0 must be run from librdkafka top directory"
        exit 1
    fi

    mkdir -p ${PWD}/packaging/rpm/cache/mock

    docker run \
           --privileged \
           -t \
           -v ${PWD}/packaging/rpm/cache/mock:/var/cache/mock \
           -v ${PWD}:/io \
           $_DOCKER_IMAGE \
           /io/packaging/rpm/mock-on-docker.sh --build $_MOCK_CONFIGS

    mkdir -p artifacts
    for MOCK_CONFIG in $_MOCK_CONFIGS ; do
        cp -vr --no-preserve=ownership packaging/rpm/arts-${MOCK_CONFIG}/*rpm artifacts/
    done

    echo "All Done"

else
    #
    # Running in docker container.
    #

    dnf install -y -q mock mock-core-configs make git

    echo "%_netsharedpath /sys:/proc" >> /etc/rpm/macros.netshared

    pushd /io/packaging/rpm

    for MOCK_CONFIG in $_MOCK_CONFIGS ; do
        cfg_file=/etc/mock/${MOCK_CONFIG}.cfg
        if [[ ! -f $cfg_file ]]; then
            echo "Error: Mock config $cfg_file does not exist"
            exit 1
        fi

        echo "config_opts['plugin_conf']['bind_mount_enable'] = False" >> $cfg_file
        echo "config_opts['docker_unshare_warning'] = False" >> $cfg_file
        echo "Building $MOCK_CONFIG in $PWD"
        cat $cfg_file

        echo "Setting git safe.directory"
        git config --global --add safe.directory /io

        export MOCK_CONFIG=$MOCK_CONFIG
        make all

        echo "Done building $MOCK_CONFIG: copying artifacts"
        artdir="arts-$MOCK_CONFIG"
        mkdir -p "$artdir"
        make ARTIFACTS_DIR="$artdir" copy-artifacts

    done

    popd
    echo "Done"
fi

exit 0
