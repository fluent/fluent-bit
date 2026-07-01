#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

readonly BUILD_CONTENT="/tmp/build_content"
readonly WABT_VER=1.0.31
readonly WABT_FILE="wabt-${WABT_VER}-ubuntu.tar.gz"
readonly CMAKE_VER=3.25.1
readonly CMAKE_FILE="cmake-${CMAKE_VER}-Linux-x86_64.sh"
readonly BINARYEN_VER=version_111
readonly BINARYEN_FILE="binaryen-${BINARYEN_VER}-x86_64-linux.tar.gz"
readonly BAZEL_VER=6.0.0
readonly BAZEL_FILE=bazel-${BAZEL_VER}-installer-linux-x86_64.sh

function DEBUG() {
  env | grep -q "\<DEBUG\>"
}

#
# install dependency
function install_deps() {
  apt update
  apt install -y lsb-release wget software-properties-common \
      build-essential git tree zip unzip
}

#
# install wabt
function install_wabt() {
  if [[ ! -f ${WABT_FILE} ]]; then
    wget https://github.com/WebAssembly/wabt/releases/download/${WABT_VER}/${WABT_FILE}
  fi

  tar zxf ${WABT_FILE} -C /opt
  ln -sf /opt/wabt-${WABT_VER} /opt/wabt
}

#
# install cmake
function install_cmake() {
  if [[ ! -f cmake-${CMAKE_VER}-Linux-x86_64.sh ]]; then
    wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/${CMAKE_FILE}
  fi

  chmod a+x ${CMAKE_FILE}
  mkdir /opt/cmake
  ./${CMAKE_FILE} --prefix=/opt/cmake --skip-license
  ln -sf /opt/cmake/bin/cmake /usr/local/bin/cmake
}

#
# install emsdk
function install_emsdk() {
  cd /opt
  git clone https://github.com/emscripten-core/emsdk.git
  cd emsdk
  git pull
  ./emsdk install 3.1.28
  ./emsdk activate 3.1.28
  echo "source /opt/emsdk/emsdk_env.sh" >> "${HOME}"/.bashrc
}

#
# install binaryen
function install_binaryen() {
  if [[ ! -f ${BINARYEN_FILE} ]]; then
    wget https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VER}/${BINARYEN_FILE}
  fi

  tar zxf ${BINARYEN_FILE} -C /opt
  ln -sf /opt/binaryen-${BINARYEN_VER} /opt/binaryen
}

#
# install bazel
function install_bazel() {
  if [[ ! -f ${BAZEL_FILE} ]]; then
    wget https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VER}/${BAZEL_FILE}
  fi

  chmod a+x ${BAZEL_FILE}
  ./${BAZEL_FILE}
}

#
# MAIN
DEBUG && set -xevu
if [[ ! -d ${BUILD_CONTENT} ]]; then
  mkdir ${BUILD_CONTENT}
fi

cd ${BUILD_CONTENT} || exit
if DEBUG; then
  "$@"
else
  install_deps \
    && install_bazel \
    && install_binaryen \
    && install_cmake \
    && install_emsdk \
    && install_wabt
fi
cd - > /dev/null || exit
DEBUG && set +xevu
