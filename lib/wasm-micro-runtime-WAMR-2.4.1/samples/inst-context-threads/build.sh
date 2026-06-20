#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

CURR_DIR=$PWD
WAMR_DIR=${PWD}/../..
OUT_DIR=${PWD}/out

WASM_APPS=${PWD}/wasm-apps


rm -rf ${OUT_DIR}
mkdir ${OUT_DIR}
mkdir ${OUT_DIR}/wasm-apps


echo "#####################build inst-context project"
cd ${CURR_DIR}
mkdir -p cmake_build
cd cmake_build
cmake ..
make -j ${nproc}
if [ $? != 0 ];then
    echo "BUILD_FAIL inst-context exit as $?\n"
    exit 2
fi

cp -a inst-context ${OUT_DIR}

echo -e "\n"

echo "#####################build wasm apps"

cd ${WASM_APPS}

for i in `ls *.c`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

# use WAMR SDK to build out the .wasm binary
# require wasi-sdk with wasi-threads support. (wasi-sdk-20.0 or later)
/opt/wasi-sdk/bin/clang     \
        --target=wasm32-wasi-threads \
        -pthread \
        -Wl,--import-memory \
        -Wl,--export-memory \
        -Wl,--max-memory=655360 \
        -o ${OUT_DIR}/wasm-apps/${OUT_FILE} ${APP_SRC}


if [ -f ${OUT_DIR}/wasm-apps/${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
echo "####################build wasm apps done"
