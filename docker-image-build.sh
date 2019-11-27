#!/bin/sh

VERSION="1.3"
IMAGE_NAME="fluent/fluent-bit"

docker build --build-arg inotify_mode=inotify_on -t ${IMAGE_NAME}:${VERSION} -f ./Dockerfile .
docker build --build-arg inotify_mode=inotify_on -t ${IMAGE_NAME}:${VERSION}-debug -f ./Dockerfile.debug .

docker build --build-arg inotify_mode=inotify_off -t ${IMAGE_NAME}-inotify-disabled:${VERSION} -f ./Dockerfile .
docker build --build-arg inotify_mode=inotify_off -t ${IMAGE_NAME}-inotify-disabled:${VERSION}-debug -f ./Dockerfile.debug .
