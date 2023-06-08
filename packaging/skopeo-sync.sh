#!/bin/bash
set -eu

# Simple script to handle skopeo copying of images from staging to release registries.
# Simplifies usage in actions and handles any GPG set up.
#
# Optional variables:
# GPG_KEY - the name/fingerprint of a locally installed GPG key to use for signing images on release.
#
# Required to be set prior to calling this:
# VERSION - the tag we are releasing, e.g. 1.9.1
# RELEASE_CREDS - the credentials required to push images to the release registry
# STAGING_IMAGE_NAME - the source image to pull from staging
# RELEASE_IMAGE_NAME - the destination image for pushing to release

# We do it tag-by-tag as Cosign signatures cause problems for Skopeo plus
# this prevents us releasing the wrong subset of images in staging if we use `sync`
declare -a TAGS_TO_SYNC=("$VERSION" "latest" "$VERSION-debug" "latest-debug")

for TAG in "${TAGS_TO_SYNC[@]}" ; do
    # Copy all architectures
    # Use the skopeo image as it is not available until Ubuntu 20.10
    if [[ -z "$GPG_KEY" ]]; then
        docker run --rm  \
            quay.io/skopeo/stable:latest \
            copy \
            --all \
            --src-no-creds \
            --dest-creds "$RELEASE_CREDS" \
            "docker://$STAGING_IMAGE_NAME:$TAG" \
            "docker://$RELEASE_IMAGE_NAME:$TAG"
    else
        # We first need to import the key then copy over the image all in the same container.
        rm -rf /tmp/skopeo-gpg/
        mkdir -p /tmp/skopeo-gpg/
        gpg --output /tmp/skopeo-gpg/private.gpg --export-secret-key --armor --export "$GPG_KEY"
        # There's no good way to import the key into the container currenty so we hijack the entrypoint.
        docker run --rm  \
            -v /tmp/skopeo-gpg:/skopeo-gpg \
            --entrypoint=/bin/bash \
            quay.io/skopeo/stable:latest -c "\
                gpg --import /skopeo-gpg/private.gpg && \
                skopeo \
                copy \
                --all --remove-signatures \
                --sign-by $GPG_KEY \
                --src-no-creds \
                --dest-creds $RELEASE_CREDS \
                docker://$STAGING_IMAGE_NAME:$TAG \
                docker://$RELEASE_IMAGE_NAME:$TAG "
    fi
done