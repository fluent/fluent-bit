#!/bin/bash
set -eux

SOURCE_DIR=${SOURCE_DIR:-$HOME/apt}
WINDOWS_SOURCE_DIR=${WINDOWS_SOURCE_DIR:-ignore}
VERSION=${VERSION:-$1}
MAJOR_VERSION=${MAJOR_VERSION:-}

if [[ -z "$VERSION" ]]; then
    echo "Missing VERSION value"
    exit 1
fi

if [[ -z "$MAJOR_VERSION" ]]; then
    MAJOR_VERSION=${VERSION%.*}
fi

echo "Publishing source and Windows packages for $VERSION (major: $MAJOR_VERSION)"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Missing source directory: $SOURCE_DIR"
fi

RELEASES_DIR=${RELEASES_DIR:-/var/www/releases.fluentbit.io}
if [[ -d "$RELEASES_DIR/releases" ]]; then
    echo "Using legacy releases linkage"
    RELEASES_DIR="$RELEASES_DIR/releases" 
fi

# Handle the JSON schema by copying in the new versions (if they exist).
echo "Updating JSON schema"
find "$SOURCE_DIR/" -iname "fluent-bit-schema*$VERSION*.json" -exec cp -vf "{}" "$RELEASES_DIR/$MAJOR_VERSION/" \;

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
    cp -vf "$WINDOWS_SOURCE_DIR"/*$VERSION* "$RELEASES_DIR/$MAJOR_VERSION/"
else
    # Windows - we do want word splitting and ensure some files exist
    if compgen -G "$SOURCE_DIR/windows/*$VERSION*" > /dev/null; then
        echo "Copying Windows artefacts"
        # shellcheck disable=SC2086
        cp -vf "$SOURCE_DIR"/windows/*$VERSION* "$RELEASES_DIR/$MAJOR_VERSION/"
    else
        echo "Missing Windows builds"
    fi
fi

# Source - we do want word splitting and ensure some files exist
if compgen -G "$SOURCE_DIR/source/*$VERSION*" > /dev/null; then
    echo "Copying source artefacts"
    # shellcheck disable=SC2086
    cp -vf "$SOURCE_DIR"/source/*$VERSION* "$RELEASES_DIR/$MAJOR_VERSION/"
else
    echo "Missing source artefacts"
fi
