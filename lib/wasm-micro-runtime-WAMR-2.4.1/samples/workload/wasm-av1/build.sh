#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/bin/bash

####################################
#   build wasm-av1 sample   #
####################################
if [ ! -d "${EMSDK}" ]; then
    echo "can not find emsdk. "
    echo "please refer to https://emscripten.org/docs/getting_started/downloads.html "
    echo "to install it, or active it by 'source <emsdk_dir>emsdk_env.sh'"
    exit
fi

set -xe

EMSDK_WASM_DIR="${EMSDK}/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten"
BUILD_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${BUILD_SCRIPT_DIR}/out"
WASM_AV1_DIR="${BUILD_SCRIPT_DIR}/wasm-av1"

WAMR_PLATFORM_DIR="${BUILD_SCRIPT_DIR}/../../../product-mini/platforms"
IWASM_CMD="${WAMR_PLATFORM_DIR}/linux/build/iwasm"

WAMRC_DIR="${BUILD_SCRIPT_DIR}/../../../wamr-compiler"
WAMRC_CMD="${WAMRC_DIR}/build/wamrc"

function Clear_Before_Exit
{
    [[ -f ${WASM_AV1_DIR}/wasm-av1.patch ]] &&
       rm -f ${WASM_AV1_DIR}/wasm-av1.patch
    # resume the libc.a under EMSDK_WASM_DIR
    cd ${EMSDK_WASM_DIR}
    mv libc.a.bak libc.a
}

# 1.hack emcc
cd ${EMSDK_WASM_DIR}
# back up libc.a
cp libc.a libc.a.bak
# delete some objects in libc.a
emar d libc.a fopen.o
emar d libc.a fread.o
emar d libc.a feof.o
emar d libc.a fclose.o

# 2. build wasm-av1
cd ${BUILD_SCRIPT_DIR}
# 2.1 clone wasm-av1 repo from Github
if [ ! -d "wasm-av1" ]; then
    git clone https://github.com/GoogleChromeLabs/wasm-av1.git
fi

# 2.2 copy the wasm-av1.patch to wasm-av1 and apply the patch
cd ${WASM_AV1_DIR}
cp -a ${BUILD_SCRIPT_DIR}/wasm-av1.patch .
git checkout Makefile
git checkout test.c
git checkout third_party/aom

if [[ $(git apply wasm-av1.patch 2>&1) =~ "error" ]]; then
    echo "git apply patch failed, please check wasm-av1 related changes..."
    Clear_Before_Exit
    exit 0
fi

make testavx -j 4

# remove patch file and recover emcc libc.a after building
Clear_Before_Exit

# 2.3 copy /make/gen target files to out/
rm -rf ${OUT_DIR} && mkdir ${OUT_DIR}
cp -a ${WASM_AV1_DIR}/testavx.wasm ${OUT_DIR}/

# 3. compile wasm-av1.wasm to wasm-av1.aot with wamrc
# 3.1 build wamr-compiler
cd ${WAMRC_DIR}
./build_llvm.sh
rm -fr build && mkdir build
cd build && cmake ..
make
# 3.2 compile wasm-av1.wasm to wasm-av1.aot
cd ${OUT_DIR}
${WAMRC_CMD} -o testavx.aot testavx.wasm

# 4. build iwasm with pthread and libc_emcc enable
cd ${WAMR_PLATFORM_DIR}/linux
rm -fr build && mkdir build
cd build && cmake .. -DWAMR_BUILD_LIB_PTHREAD=1 -DWAMR_BUILD_LIBC_EMCC=1
make

# 5. run wasm-av1 with iwasm
echo "---> run testav1.aot with iwasm"
cd ${OUT_DIR}
${IWASM_CMD} testavx.aot ../wasm-av1/third_party/samples/elephants_dream_480p24.ivf

