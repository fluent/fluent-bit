#!/bin/bash
set -eux

# release-build-docker-images
JOB=${JOB:-release-build-distro-packages}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-minioadmin}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-minioadmin}
AWS_S3_BUCKET_STAGING=${AWS_S3_BUCKET_STAGING:-fluentbit-ci-staging}
AWS_S3_BUCKET_RELEASE=${AWS_S3_BUCKET_RELEASE:-fluentbit-ci-release}

GPG_PRIVATE_KEY=$(gpg --armor --export-secret-key $USER@calyptia.com -w0)

rm -rf workflow/
mkdir -p workflow/

act --privileged --bind \
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
    -s AWS_S3_BUCKET_RELEASE="$AWS_S3_BUCKET_RELEASE" \
    -s GPG_PRIVATE_KEY="$GPG_PRIVATE_KEY" \
    --env AWS_S3_ENDPOINT="http://localhost:9000" \
    -j "${JOB}"
