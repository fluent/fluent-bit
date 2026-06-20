#!/bin/bash

if [ -z "$1" ]; then
    echo "Specify archive name"
    exit 1
fi

OS=$(uname -s)

echo "$OS"
if [ "$OS" == "Darwin" ]; then
    echo "Using gtar for concatenate option"
    TAR=gtar
else
    TAR=tar
fi

ROOT_ARCHIVE_NAME=$1

git archive --prefix "$ROOT_ARCHIVE_NAME/" -o "$ROOT_ARCHIVE_NAME.tar" HEAD
git submodule foreach --recursive "git archive --prefix=$ROOT_ARCHIVE_NAME/\$path/ --output=\$sha1.tar HEAD && $TAR --concatenate --file=$(pwd)/$ROOT_ARCHIVE_NAME.tar \$sha1.tar && rm \$sha1.tar"

gzip "$ROOT_ARCHIVE_NAME.tar"
