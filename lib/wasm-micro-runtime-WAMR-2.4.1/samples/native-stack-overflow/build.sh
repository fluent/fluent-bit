#! /bin/sh

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

CURR_DIR=$PWD
WAMR_DIR=${PWD}/../..
OUT_DIR=${PWD}/out

WASM_APPS=${PWD}/wasm-apps


rm -rf ${OUT_DIR}
mkdir ${OUT_DIR}
mkdir ${OUT_DIR}/wasm-apps


echo "##################### build (default)"
cd ${CURR_DIR}
mkdir -p cmake_build
cd cmake_build
cmake ..
make -j 4
if [ $? != 0 ];then
    echo "BUILD_FAIL native-stack-overflow exit as $?\n"
    exit 2
fi
cp -a native-stack-overflow ${OUT_DIR}

echo "##################### build (WAMR_DISABLE_HW_BOUND_CHECK=1)"
cd ${CURR_DIR}
mkdir -p cmake_build_disable_hw_bound
cd cmake_build_disable_hw_bound
cmake -D WAMR_DISABLE_HW_BOUND_CHECK=1 ..
make -j 4
if [ $? != 0 ];then
    echo "BUILD_FAIL native-stack-overflow exit as $?\n"
    exit 2
fi
cp -a native-stack-overflow ${OUT_DIR}/native-stack-overflow.WAMR_DISABLE_HW_BOUND_CHECK

echo "##################### signature shared lib"
cd ${CURR_DIR}
cc -I ../../core/iwasm/include -shared -o ${OUT_DIR}/signature.so \
src/signature.c

echo

echo "##################### build wasm apps"

cd ${WASM_APPS}

for i in `ls *.c`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

# use WAMR SDK to build out the .wasm binary
/opt/wasi-sdk/bin/clang     \
        -mexec-model=reactor \
        -Os -z stack-size=4096 -Wl,--initial-memory=65536 \
        -Wl,--allow-undefined \
        -o ${OUT_DIR}/wasm-apps/${OUT_FILE} ${APP_SRC}

if [ -f ${OUT_DIR}/wasm-apps/${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
echo "#################### build wasm apps done"

echo "#################### aot-compile"
WAMRC=${WAMR_DIR}/wamr-compiler/build/wamrc
${WAMRC} \
-o ${OUT_DIR}/wasm-apps/${OUT_FILE}.aot \
--size-level=0 \
${OUT_DIR}/wasm-apps/${OUT_FILE}

echo "#################### aot-compile w/ signature"
WAMRC=${WAMR_DIR}/wamr-compiler/build/wamrc
${WAMRC} \
-o ${OUT_DIR}/wasm-apps/${OUT_FILE}.aot.signature \
--size-level=0 \
--native-lib=${OUT_DIR}/signature.so \
${OUT_DIR}/wasm-apps/${OUT_FILE}

echo "#################### aot-compile (--bounds-checks=1)"
${WAMRC} \
-o ${OUT_DIR}/wasm-apps/${OUT_FILE}.aot.bounds-checks \
--size-level=0 \
--bounds-checks=1 \
${OUT_DIR}/wasm-apps/${OUT_FILE}

echo "#################### aot-compile (--bounds-checks=1) w/ signature"
${WAMRC} \
-o ${OUT_DIR}/wasm-apps/${OUT_FILE}.aot.signature.bounds-checks \
--size-level=0 \
--native-lib=${OUT_DIR}/signature.so \
--bounds-checks=1 \
${OUT_DIR}/wasm-apps/${OUT_FILE}
