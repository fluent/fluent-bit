#!/bin/bash
set -eu

MAJOR_VERSION=${MAJOR_VERSION:?}
PACKAGE_DIR=${PACKAGE_DIR:?}

pushd "$PACKAGE_DIR"

for i in *.exe
do
    echo "$i"
    sha256sum "$i" > "$i".sha256
done

for i in *.zip
do
    echo "$i"
    sha256sum "$i" > "$i".sha256
done
popd

sudo cp -v "$PACKAGE_DIR"/* /var/www/releases.fluentbit.io/releases/"$MAJOR_VERSION"/
