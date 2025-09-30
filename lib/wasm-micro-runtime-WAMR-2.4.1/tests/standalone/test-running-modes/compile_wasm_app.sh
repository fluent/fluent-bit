#!/bin/bash
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

set -e
readonly COMPILE_CMD="/opt/wasi-sdk/bin/clang"

if ! test -x ${COMPILE_CMD}; then
  echo "wasi-sdk could not be found"
  exit
fi

${COMPILE_CMD} -O3 \
  -z stack-size=8192 -nostdlib -Wl,--allow-undefined -Wl,--no-entry -Wl,--initial-memory=65536 \
  -o wasm-apps/mytest.wasm wasm-apps/mytest.c \
  -Wl,--export=__main_argc_argv

${COMPILE_CMD} -O3 \
  -Wl,--no-entry -nostdlib \
  -o wasm-apps/hello.wasm wasm-apps/hello.c \
  -Wl,--export=echo
