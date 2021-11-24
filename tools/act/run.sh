#!/bin/bash
set -eux

# release-build-docker-images
JOB=${JOB:-release-build-distro-packages}

act --privileged \
    -P ubuntu-latest=nektos/act-environments-ubuntu:18.04 \
    -P ubuntu-18.04=nektos/act-environments-ubuntu:18.04 \
    --rm \
    -s GITHUB_TOKEN="${GITHUB_TOKEN}" \
    -j "${JOB}"
