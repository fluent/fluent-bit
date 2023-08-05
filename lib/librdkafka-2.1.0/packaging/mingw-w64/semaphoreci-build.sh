#!/bin/bash
#

set -ex

if [[ $1 == "--static" ]]; then
    linkage="static"
    shift
else
linkage="dynamic"
fi

if [[ -z $1 ]]; then
    echo "Usage: $0 [--static] <relative-path-to-output-librdkafka.tgz>"
    exit 1
fi

archive="${PWD}/$1"

source ./packaging/mingw-w64/travis-before-install.sh

if [[ $linkage == "static" ]]; then
    ./packaging/mingw-w64/configure-build-msys2-mingw-static.sh
else
    ./packaging/mingw-w64/configure-build-msys2-mingw.sh
fi


./packaging/mingw-w64/run-tests.sh

pushd dest
tar cvzf $archive .
sha256sum $archive
popd




