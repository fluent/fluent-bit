#!/usr/bin/env bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

readonly SCRIPT_PATH=$(dirname "$(realpath "$0")")
readonly ROOT=$(realpath "${SCRIPT_PATH}"/../../../)
readonly CURRENT_PATH=$(pwd)
readonly CURRENT_RELATIVE_ROOT=$(realpath --relative-base ${ROOT} ${CURRENT_PATH})
readonly VARIANT=$(lsb_release -c | awk '{print $2}')

docker build \
  --build-arg VARIANT=${VARIANT} \
  --memory 4G --cpu-quota 50000 \
  -t wamr_dev_${VARIANT}:0.1 -f "${ROOT}"/.devcontainer/Dockerfile "${ROOT}"/.devcontainer &&
  docker run --rm -it \
    --memory 4G \
    --cpus ".5" \
    --name workload_build_env \
    --mount type=bind,source="${ROOT}",target=/workspace \
    wamr_dev_${VARIANT}:0.1 \
    /bin/bash -c "\
      pwd \
      && pushd ${CURRENT_RELATIVE_ROOT} \
      && rm -rf build \
      && mkdir build \
      && pushd build \
      && cmake .. \
      && cmake --build . --config Release \
      && popd \
      && popd \
      && echo 'Go and find out results under ${CURRENT_RELATIVE_ROOT}/build' "
