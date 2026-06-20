#!/bin/bash
set -eu

# Generate checksums for local Windows binaries

SOURCE_DIR=${SOURCE_DIR:?}

pushd "$SOURCE_DIR"
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
