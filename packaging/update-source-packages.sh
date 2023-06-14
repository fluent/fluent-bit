#!/bin/bash
set -eux

# We provide the source code as a standalone checksummed package along with the JSON schema and AppVeyor binaries.
# This is hosted at releases.fluentbit.io

WINDOWS_SOURCE_DIR=${WINDOWS_SOURCE_DIR:-ignore}
VERSION=${VERSION:-$1}
MAJOR_VERSION=${MAJOR_VERSION:-}
SOURCE_DIR=${SOURCE_DIR:?}
TARGET_DIR=${TARGET_DIR:?}

if [[ -z "$VERSION" ]]; then
    echo "Missing VERSION value"
    exit 1
fi

if [[ -z "$MAJOR_VERSION" ]]; then
    MAJOR_VERSION=${VERSION%.*}
fi

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Missing source directory: $SOURCE_DIR"
    exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Missing target directory: $TARGET_DIR"
    exit 1
fi
# create MAJOR_VERSION dir if not exist
mkdir -p "$TARGET_DIR/$MAJOR_VERSION"

# Handle the JSON schema by copying in the new versions (if they exist).
echo "Updating JSON schema"
find "$SOURCE_DIR/" -iname "fluent-bit-schema*$VERSION*.json" -exec cp -vf "{}" "$TARGET_DIR/$MAJOR_VERSION/" \;

# Intended for AppVeyor usage
if [[ -d "$WINDOWS_SOURCE_DIR" ]]; then
    echo "Using overridden Windows directory: $WINDOWS_SOURCE_DIR"
    pushd "$WINDOWS_SOURCE_DIR"
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
    # shellcheck disable=SC2086
    cp -vf "$WINDOWS_SOURCE_DIR"/*$VERSION* "$TARGET_DIR/$MAJOR_VERSION/"
else
    # Windows - we do want word splitting and ensure some files exist
    if compgen -G "$SOURCE_DIR/windows/*$VERSION*" > /dev/null; then
        echo "Copying Windows artefacts"
        # shellcheck disable=SC2086
        cp -vf "$SOURCE_DIR"/windows/*$VERSION* "$TARGET_DIR/$MAJOR_VERSION/"
    else
        echo "Missing Windows builds"
    fi
fi

# Source - we do want word splitting and ensure some files exist
if compgen -G "$SOURCE_DIR/source-$VERSION*" > /dev/null; then
    echo "Copying source artefacts"
    # shellcheck disable=SC2086
    cp -vf "$SOURCE_DIR"/source-$VERSION* "$TARGET_DIR/$MAJOR_VERSION/"
elif compgen -G "$SOURCE_DIR/source/*$VERSION*" > /dev/null; then
    echo "Copying (legacy) source artefacts"
    # shellcheck disable=SC2086
    cp -vf "$SOURCE_DIR"/source/*$VERSION* "$TARGET_DIR/$MAJOR_VERSION/"
else
    echo "Missing source artefacts"
fi
