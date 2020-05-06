#!/bin/bash
#
# Build librdkafka for different distros to produce distro-specific artifacts.
# Requires docker.
#

set -e

distro=$1

case $distro in
    centos)
        packaging/rpm/mock-on-docker.sh
        ;;
    debian)
        docker run -it -v "$PWD:/v" microsoft/dotnet:2-sdk /v/packaging/tools/build-debian.sh /v /v/artifacts/librdkafka-debian9.tgz
        ;;
    alpine)
        packaging/alpine/build-alpine.sh
        ;;
    *)
        echo "Usage: $0 <centos|debian|alpine|travis>"
        exit 1
        ;;
esac
