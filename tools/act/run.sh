#!/bin/bash
set -eux

# release-build-docker-images
JOB=${JOB:-release-build-distro-packages}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-minioadmin}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-minioadmin}
AWS_S3_BUCKET_STAGING=${AWS_S3_BUCKET_STAGING:-fluentbit-ci-testbucket}

act --privileged \
    -P ubuntu-latest=nektos/act-environments-ubuntu:18.04 \
    -P ubuntu-18.04=nektos/act-environments-ubuntu:18.04 \
    --rm \
    -s GITHUB_TOKEN="${GITHUB_TOKEN}" \
    -s DOCKERHUB_TOKEN="$DOCKERHUB_TOKEN" \
    -s DOCKERHUB_USERNAME="$DOCKERHUB_USERNAME" \
    -s DOCKERHUB_ORGANIZATION="$DOCKERHUB_ORGANIZATION" \
    -s AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
    -s AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    -s AWS_S3_BUCKET_STAGING="$AWS_S3_BUCKET_STAGING" \
    --env AWS_S3_ENDPOINT="http://localhost:9000" \
    -j "${JOB}"
