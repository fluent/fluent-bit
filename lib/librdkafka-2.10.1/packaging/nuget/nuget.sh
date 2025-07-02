#!/bin/bash
#
#
# Front-end for nuget that runs nuget in a docker image.

set -ex

if [[ -f /.dockerenv ]]; then
    echo "Inside docker"

    pushd $(dirname $0)

    nuget $*

    popd

else
    echo "Running docker image"
    docker run -v $(pwd):/io mono:latest /io/$0 $*
fi

