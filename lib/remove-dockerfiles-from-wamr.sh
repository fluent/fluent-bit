#!/bin/sh

# Currently, wasm-micro-runtime's Dockerfiles are not-well following hadolint rules.
# So, we should remove them for now.
DIR="$( cd "$( dirname "$0" )" && pwd )"
ls ${DIR}/wasm-micro-runtime-*/**/Dockerfile | xargs rm -f
ls ${DIR}/wasm-micro-runtime-*/**/**/**/Dockerfile | xargs rm -f
ls ${DIR}/wasm-micro-runtime-*/**/**/**/**/Dockerfile | xargs rm -f
