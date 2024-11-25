#!/bin/sh

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CUR_DIR=$(cd $(dirname $0) && pwd -P)
ROOT_DIR=${CUR_DIR}/../../..

UNAME=$(uname -s|tr A-Z a-z)
WAMR_BUILD_PLATFORM=${WAMR_BUILD_PLATFORM:-${UNAME}}

cd ${ROOT_DIR}/product-mini/platforms/${WAMR_BUILD_PLATFORM}

mkdir -p build && cd build
cmake \
    -DWAMR_BUILD_DEBUG_INTERP=1 \
    -DWAMR_BUILD_LIB_PTHREAD=1 \
    -DWAMR_BUILD_LIB_WASI_THREADS=1 \
    -DWAMR_BUILD_LIB_WASI=1 \
    ..
make -j

case ${UNAME} in
darwin)
    LIBNAME=libiwasm.dylib
    ;;
*)
    LIBNAME=libiwasm.so
    ;;
esac
cp ${LIBNAME} ${CUR_DIR}/../src/wamr/libs

cd ${ROOT_DIR}/language-bindings/python/src/wamr/wamrapi
ctypesgen \
${ROOT_DIR}/core/iwasm/include/wasm_export.h \
-l ../libs/${LIBNAME} \
-o iwasm.py
