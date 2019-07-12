#!/bin/bash
#
#

# Run mock in docker

set -ex

_DOCKER_IMAGE=centos:7
export MOCK_CONFIG=epel-7-x86_64

if [[ ! -f /.dockerenv ]]; then
    #
    # Running on host, fire up a docker container a run it.
    #

    if [[ ! -f configure.librdkafka ]]; then
        echo "$0 must be run from librdkafka top directory"
        exit 1
    fi

    docker run --privileged=true -t -v $(pwd):/io \
          $_DOCKER_IMAGE /io/packaging/rpm/mock-on-docker.sh

    pushd packaging/rpm
    make copy-artifacts
    popd

else

    yum install -y python mock make git

    cfg_file=/etc/mock/${MOCK_CONFIG}.cfg
    ls -la /etc/mock
    echo "config_opts['plugin_conf']['bind_mount_enable'] = False" >> $cfg_file
    echo "config_opts['package_manager'] = 'yum'" >> $cfg_file
    cat $cfg_file
    pushd /io/packaging/rpm
    make all
    popd
fi
