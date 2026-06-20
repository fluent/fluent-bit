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


echo "##################### build terminate project"
cd ${CURR_DIR}
mkdir -p cmake_build
cd cmake_build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j ${nproc}
if [ $? != 0 ];then
    echo "BUILD_FAIL terminate exit as $?\n"
    exit 2
fi

cp -a terminate ${OUT_DIR}

printf "\n"

echo "##################### build wasm apps"

cd ${WASM_APPS}

for i in `ls *.wat`
do
APP_SRC="$i"
OUT_FILE=${i%.*}.wasm

# Note: the CI installs wabt in /opt/wabt
if type wat2wasm; then
    WAT2WASM=${WAT2WASM:-wat2wasm}
elif [ -x /opt/wabt/bin/wat2wasm ]; then
    WAT2WASM=${WAT2WASM:-/opt/wabt/bin/wat2wasm}
fi

${WAT2WASM} -o ${OUT_DIR}/wasm-apps/${OUT_FILE} ${APP_SRC}

# aot
# wamrc -o ${OUT_DIR}/wasm-apps/${OUT_FILE}.aot ${OUT_DIR}/wasm-apps/${OUT_FILE}
# mv ${OUT_DIR}/wasm-apps/${OUT_FILE}.aot ${OUT_DIR}/wasm-apps/${OUT_FILE}

if [ -f ${OUT_DIR}/wasm-apps/${OUT_FILE} ]; then
        echo "build ${OUT_FILE} success"
else
        echo "build ${OUT_FILE} fail"
fi
done
echo "##################### build wasm apps done"
